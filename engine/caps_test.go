package engine_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// wide turns the domain into n hostnames.
type wide struct{ n int }

func (*wide) Name() string             { return "test-wide" }
func (*wide) Info() catalog.Info       { return catalog.Info{Kind: catalog.Passive} }
func (*wide) Inputs() []types.SeedType { return []types.SeedType{types.TypeDomain, types.TypeHostname} }
func (*wide) Outputs() []string        { return nil }
func (c *wide) Run(_ context.Context, seed types.Seed, _ func(types.Observation) error) (types.RunMeta, error) {
	var hints []types.Seed
	if seed.Type == types.TypeDomain {
		for i := 0; i < c.n; i++ {
			hints = append(hints, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": fmt.Sprintf("h%d.example.org", i)}})
		}
	}
	return types.RunMeta{Status: types.StatusOK, NextHints: hints}, nil
}

func capsRun(t *testing.T, st *store.Store, c catalog.Collector, b engine.Budgets) engine.Caps {
	t.Helper()
	cat := catalog.New()
	cat.MustRegister(c)
	eng := &engine.Engine{Cat: cat, Store: st}
	if err := eng.RunLocal(context.Background(), []types.Seed{{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}}, b); err != nil {
		t.Fatal(err)
	}
	return eng.Caps()
}

func capsStore(t *testing.T, depth int) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.BeginRun("r", depth, 0); err != nil {
		t.Fatal(err)
	}
	return st
}

// A run has no cap on the tasks it starts unless -max-items says so: an
// estate of thousands of names is mapped in one run.
func TestDefaultBudgetsDoNotCapTheTasks(t *testing.T) {
	st := capsStore(t, 4)
	caps := capsRun(t, st, &wide{n: 3000}, engine.DefaultBudgets())
	if left := st.TasksLeft(); left != 0 || caps != (engine.Caps{}) {
		t.Errorf("%d tasks left after a run with no cap, caps %+v", left, caps)
	}
}

// -max-items holds for each run, as -max-requests does: a resume given the
// same cap starts that many more tasks, and a few resumes finish the run.
func TestMaxItemsHoldsForEachRun(t *testing.T) {
	st := capsStore(t, 4)
	b := engine.DefaultBudgets()
	b.MaxItems = 20
	caps := capsRun(t, st, &wide{n: 100}, b)
	if caps.ItemsLeft == 0 || st.TasksLeft() == 0 {
		t.Fatalf("a run capped at 20 tasks left %d, caps %+v", st.TasksLeft(), caps)
	}
	b.Resume = true
	for i := 0; st.TasksLeft() > 0; i++ {
		if i == 10 {
			t.Fatalf("%d tasks left after %d resumes at the same cap", st.TasksLeft(), i)
		}
		before := st.TasksDone()
		capsRun(t, st, &wide{n: 100}, b)
		if st.TasksDone() <= before {
			t.Fatalf("a resume at the same cap did no task: %d done before and after", before)
		}
	}
}

// What -depth left unasked is named, and a resume with a larger -depth asks it.
func TestResumeWithALargerDepthAsksWhatDepthLeft(t *testing.T) {
	st := capsStore(t, 2)
	b := engine.DefaultBudgets()
	b.MaxDepth = 2
	first := &tree{ran: map[string]int{}}
	caps := capsRun(t, st, first, b)
	if caps.DepthNames+caps.DepthURLs == 0 || caps.DepthURLs != 12 {
		t.Fatalf("caps %+v: the 12 URLs past -depth 2 are not counted", caps)
	}
	if len(first.ran) != 5 {
		t.Fatalf("ran %v", first.ran)
	}
	b.Resume, b.MaxDepth = true, 3
	second := &tree{ran: map[string]int{}}
	caps = capsRun(t, st, second, b)
	if len(second.ran) != 12 || caps.DepthURLs != 0 {
		t.Errorf("a resume at -depth 3 ran %d tasks (%v), caps %+v: want the 12 URLs asked", len(second.ran), second.ran, caps)
	}
}
