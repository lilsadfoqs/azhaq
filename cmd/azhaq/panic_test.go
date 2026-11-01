package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/catalog"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// panicker finds one thing and then fails with a bug.
type panicker struct{}

func (panicker) Name() string             { return "test-panic" }
func (panicker) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }
func (panicker) Outputs() []string        { return []string{"test-found"} }
func (panicker) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	_ = emit(types.Observation{Kind: "test-found", Source: "test", Payload: []byte(`{"n":1}`)})
	var none []int
	_ = none[len(seed.Key())]
	return types.RunMeta{}, nil
}

// A collector that panics fails its task: the run goes on, keeps what was
// found, lists the panic with the failures and exits 3, and the ledger is
// sealed.
func TestRunSurvivesACollectorPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>site</title><a href="/next">next</a>`))
	}))
	defer srv.Close()
	extraCollectors = func(c *catalog.Catalog) { c.MustRegister(panicker{}) }
	defer func() { extraCollectors = nil }()
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-no-paths", "-quiet", "-json", "-db", "w.db")
	if code != exitPartial {
		t.Fatalf("exit %d, want %d\n%s", code, exitPartial, errOut)
	}
	sum := lastReport(t, strings.TrimSpace(errOut))
	if sum.Complete || sum.Exit != exitPartial {
		t.Fatalf("a run with a failed collector is not complete: %+v", sum)
	}
	tasks := 0
	for i := range sum.Failed {
		if sum.Failed[i].Collector == "test-panic" {
			tasks += sum.Failed[i].Count
			if !strings.HasPrefix(sum.Failed[i].Error, "panic: runtime error: index out of range") || !strings.Contains(sum.Failed[i].Error, "panic_test.go") {
				t.Errorf("the panic and where it was: %q", sum.Failed[i].Error)
			}
			if sum.Failed[i].Fanout || sum.Failed[i].Partial {
				t.Errorf("a bug is never set aside: %+v", sum.Failed[i])
			}
		}
	}
	if tasks < 2 {
		t.Fatalf("want the panic listed once per task (the page and /next): %+v", sum.Failed)
	}
	st, err := store.OpenExisting("w.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, _ := st.Observations()
	var found, http int
	for _, o := range obs {
		switch {
		case o.Kind == "test-found":
			found++
		case o.Collector == "azhaq-http" && o.Kind != "error":
			http++
		}
	}
	if found < 2 || http < 2 {
		t.Errorf("results found before and beside the panic are kept: %d from the collector, %d pages", found, http)
	}
	if err := cmdLedger([]string{"-verify", filepath.Join(".", "w.db.ledger.jsonl")}); err != nil {
		t.Errorf("the ledger is sealed: %v", err)
	}
}
