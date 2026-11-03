package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// archive stands for azhaq-urls: it hands on what an archive lists,
// archived URLs first, before the application's own pages.
type fakeArchive struct{ base string }

func (a *fakeArchive) Name() string              { return "azhaq-fake-archive" }
func (a *fakeArchive) Info() catalog.Info        { return catalog.Info{Kind: catalog.Passive} }
func (a *fakeArchive) Inputs() []types.SeedType  { return []types.SeedType{types.TypeURL} }
func (a *fakeArchive) Outputs() []string         { return []string{"url"} }
func (a *fakeArchive) Skip(seed types.Seed) bool { return seed.Key() != a.base+"/" }
func (a *fakeArchive) Run(_ context.Context, _ types.Seed, _ func(types.Observation) error) (types.RunMeta, error) {
	hint := func(p, via string) types.Seed {
		keys := map[string]string{"url": a.base + p}
		if via != "" {
			keys[types.ViaKey] = via
		}
		return types.Seed{Type: types.TypeURL, Keys: keys}
	}
	return types.RunMeta{Status: types.StatusOK, NextHints: []types.Seed{
		hint("/old/1", types.ViaArchive), hint("/old/2", types.ViaArchive), hint("/old/3", types.ViaArchive),
		hint("/page", ""), hint("/api/users", ""),
	}}, nil
}

// Under a budget, the front page and the API paths go before the pages
// links name, and what only an archive lists goes last.
func TestBudgetGoesToFrontPagesAndAPIFirst(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	cat.MustRegister(&httpcol.Collector{Client: srv.Client(), Probe: true, NoFavicon: true})
	cat.MustRegister(&fakeArchive{base: srv.URL})
	eng := &engine.Engine{Cat: cat, Store: st}
	egress.SetMaxRequests(3)
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 64, Parallel: 1}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Strings(asked)
	want := []string{"/", "/api/users", "/page"}
	if len(asked) != len(want) {
		t.Fatalf("asked %v, want %v", asked, want)
	}
	for i := range want {
		if asked[i] != want[i] {
			t.Fatalf("asked %v, want %v", asked, want)
		}
	}
}

// fakeGQL hands on two GraphQL endpoints: /graphiql, which a path sweep
// found (a guess), first, and /graphql, which a script names.
type fakeGQL struct{ base string }

func (a *fakeGQL) Name() string              { return "azhaq-fake-gql" }
func (a *fakeGQL) Info() catalog.Info        { return catalog.Info{Kind: catalog.Passive} }
func (a *fakeGQL) Inputs() []types.SeedType  { return []types.SeedType{types.TypeURL} }
func (a *fakeGQL) Outputs() []string         { return []string{"url"} }
func (a *fakeGQL) Skip(seed types.Seed) bool { return seed.Key() != a.base+"/" }
func (a *fakeGQL) Run(_ context.Context, _ types.Seed, _ func(types.Observation) error) (types.RunMeta, error) {
	return types.RunMeta{Status: types.StatusOK, NextHints: []types.Seed{
		{Type: types.TypeURL, Keys: map[string]string{"url": a.base + "/graphiql", types.KnownLocationKey: "1"}},
		{Type: types.TypeURL, Keys: map[string]string{"url": a.base + "/graphql", types.ViaKey: types.ViaScript}},
	}}, nil
}

// Under a budget of one request after the front page, the endpoint a script
// names is asked before the one only a path sweep found.
func TestBudgetGoesToNamedGraphQLBeforeGuessed(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ok</title>"))
	}))
	t.Cleanup(srv.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	cat.MustRegister(&httpcol.Collector{Client: srv.Client(), Probe: true, NoFavicon: true})
	cat.MustRegister(&fakeGQL{base: srv.URL})
	eng := &engine.Engine{Cat: cat, Store: st}
	egress.SetMaxRequests(2)
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: 2, MaxItems: 64, Parallel: 1}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0] != "/" || asked[1] != "/graphql" {
		t.Errorf("asked %v, want / then /graphql", asked)
	}
}
