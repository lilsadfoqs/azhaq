package engine_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// tree turns a domain into hosts and each host into pages, and stops the
// run (as Ctrl-C would) after a number of items.
type tree struct {
	mu     sync.Mutex
	ran    map[string]int
	stopAt int
	stop   context.CancelFunc
	n      int
	kind   *catalog.Kind // nil: Passive
}

func (*tree) Name() string { return "test-tree" }
func (c *tree) Info() catalog.Info {
	switch {
	case c.kind == nil:
		return catalog.Info{Kind: catalog.Passive}
	case *c.kind == catalog.Active:
		return catalog.Info{Kind: catalog.Active, Flag: "tree"}
	}
	return catalog.Info{Kind: *c.kind}
}
func (*tree) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeDomain, types.TypeHostname, types.TypeURL}
}
func (*tree) Outputs() []string { return nil }
func (c *tree) Run(ctx context.Context, seed types.Seed, _ func(types.Observation) error) (types.RunMeta, error) {
	c.mu.Lock()
	c.n++
	if c.stop != nil && c.n == c.stopAt {
		c.stop()
	}
	c.mu.Unlock()
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled}, ctx.Err()
	}
	c.mu.Lock()
	c.ran[seed.Key()]++
	c.mu.Unlock()
	var hints []types.Seed
	switch seed.Type {
	case types.TypeDomain:
		for i := 0; i < 4; i++ {
			hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": fmt.Sprintf("h%d.example.org", i)}})
		}
	case types.TypeHostname:
		for i := 0; i < 3; i++ {
			hints = append(hints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": fmt.Sprintf("https://%s/p%d", seed.Key(), i)}})
		}
	}
	return types.RunMeta{Status: types.StatusOK, NextHints: hints}, nil
}

func TestResumeFinishesAnInterruptedRun(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	b := engine.DefaultBudgets()
	b.Parallel = 1

	// The whole run, for reference.
	full := &tree{ran: map[string]int{}}
	run := func(c *tree, st *store.Store, ctx context.Context, resume bool) {
		cat := catalog.New()
		cat.MustRegister(c)
		bb := b
		bb.Resume = resume
		_ = (&engine.Engine{Cat: cat, Store: st}).RunLocal(ctx, seeds, bb)
	}
	st0, err := store.Open(filepath.Join(t.TempDir(), "full.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st0.Close()
	_ = st0.BeginRun("full", 4, 0)
	run(full, st0, context.Background(), false)

	path := filepath.Join(t.TempDir(), "cut.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.BeginRun("cut", 4, 0)
	ctx, cancel := context.WithCancel(context.Background())
	first := &tree{ran: map[string]int{}, stopAt: 6, stop: cancel}
	run(first, st, ctx, false)
	if left := st.TasksLeft(); left == 0 {
		t.Fatal("an interrupted run left no tasks")
	}
	st.Close()

	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _, _, ok, err := st.Resumable()
	if err != nil || !ok || id != "cut" {
		t.Fatalf("resumable: %q %v %v", id, ok, err)
	}
	st.UseRun(id)
	second := &tree{ran: map[string]int{}}
	run(second, st, context.Background(), true)

	var want, got []string
	for k := range full.ran {
		want = append(want, k)
	}
	for k := range first.ran {
		got = append(got, k)
	}
	for k := range second.ran {
		if first.ran[k] > 0 {
			t.Errorf("%s ran before the interruption and again after it", k)
		}
		got = append(got, k)
	}
	sort.Strings(want)
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("interrupted + resumed ran\n%v\nthe whole run\n%v", got, want)
	}
	if st.TasksLeft() != 0 {
		t.Errorf("%d tasks left after the resumed run", st.TasksLeft())
	}
}

// A resume honours the selection it is given: a collector it is told to skip,
// and an active one whose flag it is not given, do not run the tasks the
// stopped run left for them, and those tasks are not left over either.
func TestResumeHonoursSkipAndActiveFlags(t *testing.T) {
	seeds := []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}
	for _, tc := range []struct {
		name   string
		budget func(*engine.Budgets)
		kind   catalog.Kind
	}{
		{"skip", func(b *engine.Budgets) { b.Skip = map[string]bool{"test-tree": true} }, catalog.Passive},
		{"no flag", func(b *engine.Budgets) {}, catalog.Active},
		{"passive", func(b *engine.Budgets) { b.Passive = true }, catalog.Touch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cut.db")
			st, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			_ = st.BeginRun("cut", 4, 0)
			b := engine.DefaultBudgets()
			b.Parallel = 1
			b.Active = map[string]bool{"tree": true}
			b.Scope = scope.Rules{Allow: []string{"example.org"}}.Compile()
			ctx, cancel := context.WithCancel(context.Background())
			first := &tree{ran: map[string]int{}, stopAt: 3, stop: cancel, kind: &tc.kind}
			cat := catalog.New()
			cat.MustRegister(first)
			_ = (&engine.Engine{Cat: cat, Store: st}).RunLocal(ctx, seeds, b)
			if st.TasksLeft() == 0 {
				t.Fatal("an interrupted run left no tasks")
			}
			st.UseRun("cut")
			second := &tree{ran: map[string]int{}, kind: &tc.kind}
			cat = catalog.New()
			cat.MustRegister(second)
			b.Resume = true
			tc.budget(&b)
			if tc.name == "no flag" {
				b.Active = nil
			}
			if err := (&engine.Engine{Cat: cat, Store: st}).RunLocal(context.Background(), seeds, b); err != nil {
				t.Fatal(err)
			}
			if len(second.ran) != 0 {
				t.Errorf("the resume ran %v", second.ran)
			}
			if left := st.TasksLeft(); left != 0 {
				t.Errorf("%d tasks left after a resume that was told to leave them out", left)
			}
		})
	}
}
