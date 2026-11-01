package engine_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/engine"
	"github.com/trannghiach/azhaq/internal/collectors/httpcol"
	"github.com/trannghiach/azhaq/internal/guard"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// bugCollector emits one row, then breaks in its own goroutine, in a
// goroutine it started, or in a batch.
type bugCollector struct {
	name  string
	where string
}

func (c bugCollector) Name() string             { return c.name }
func (c bugCollector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }
func (c bugCollector) Outputs() []string        { return []string{"bug-row"} }
func (c bugCollector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	_ = emit(types.Observation{Kind: "bug-row", Source: "test", Payload: []byte(`{"from":"` + c.name + `"}`)})
	switch c.where {
	case "goroutine":
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer guard.Recover(ctx)
			defer wg.Done()
			panic("pool worker bug")
		}()
		wg.Wait()
		<-ctx.Done() // a collector waiting for what the dead worker owed
		return types.RunMeta{}, ctx.Err()
	default:
		panic("collector bug")
	}
}

type bugBatch struct{ bugCollector }

func (bugBatch) BatchSize() int { return 4 }
func (bugBatch) RunBatch(ctx context.Context, seeds []types.Seed, emit func(types.Seed, types.Observation) error) ([]types.RunMeta, error) {
	_ = emit(seeds[0], types.Observation{Kind: "bug-row", Source: "test", Payload: []byte(`{"from":"batch"}`)})
	panic("batch bug")
}

func TestPanicsFailTheTaskNotTheRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>site</title>`))
	}))
	defer srv.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	cat.MustRegister(bugCollector{"bug-own", "own"})
	cat.MustRegister(bugCollector{"bug-child", "goroutine"})
	cat.MustRegister(bugBatch{bugCollector{name: "bug-batch"}})
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	done := make(chan error, 1)
	go func() {
		done <- eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 1, MaxItems: 16})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run hung after a collector's goroutine died")
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	errs := map[string]string{}
	rows := map[string]bool{}
	pages := 0
	for _, o := range obs {
		var p map[string]string
		_ = json.Unmarshal(o.Payload, &p)
		switch {
		case o.Kind == "error":
			errs[o.Collector] = p["error"]
		case o.Kind == "bug-row":
			rows[p["from"]] = true
		case o.Collector == "azhaq-http":
			pages++
		}
	}
	for _, name := range []string{"bug-own", "bug-child", "bug-batch"} {
		if !strings.HasPrefix(errs[name], "panic: ") {
			t.Errorf("%s: failure %q, want its panic", name, errs[name])
		}
	}
	if !strings.Contains(errs["bug-own"], "collector bug") || !strings.Contains(errs["bug-child"], "pool worker bug") || !strings.Contains(errs["bug-batch"], "batch bug") {
		t.Errorf("the panic values: %v", errs)
	}
	if !rows["bug-own"] || !rows["bug-child"] || !rows["batch"] || pages == 0 {
		t.Errorf("rows before the panic and from other collectors are kept: %v, %d pages", rows, pages)
	}
	failed := engine.Failures(ents, obs)
	if len(engine.MarkFanout(failed, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://elsewhere.test/"}}})) == 0 {
		t.Fatal("no failures listed")
	}
	for _, f := range failed {
		if strings.HasPrefix(f.Error, guard.Prefix) && (f.Fanout || f.Retryable) {
			t.Errorf("a bug is not set aside or retried: %+v", f)
		}
	}
}
