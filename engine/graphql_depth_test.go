package engine_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/crawlcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/gqlcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/jscol"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// scriptLab is a page whose script calls /graphql, as DVGA's does; the
// endpoint answers introspection and refuses a bare GET as GraphQL does.
func scriptLab(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	fixture, err := os.ReadFile("../internal/gqlschema/testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	var posts, gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>lab</title><a href="/portal">portal</a>`)
		case r.URL.Path == "/portal":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>portal</title><script src="/static/app.js"></script>`)
		case r.URL.Path == "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch('/graphql', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({query: '{ systemHealth }'})})`)
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			posts.Add(1)
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(string(body), "__schema") {
				_, _ = w.Write(fixture)
				return
			}
			fmt.Fprint(w, `{"errors":[{"message":"nothing"}]}`)
		case r.URL.Path == "/graphql":
			gets.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"errors":[{"message":"Must provide query string."}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &posts, &gets
}

func mapFromRoot(t *testing.T, srv *httptest.Server, active bool, depth int) engine.MapEntry {
	t.Helper()
	fetch.Reset()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	jscol.Register(cat, srv.Client())
	crawlcol.Register(cat, srv.Client())
	cat.MustRegister(gqlcol.New(srv.Client()))
	cat.MustRegister(gqlcol.NewSchema(srv.Client()))
	eng := &engine.Engine{Cat: cat, Store: st}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
	b := engine.Budgets{MaxDepth: depth, MaxItems: 64, Scope: scope.Rules{Allow: []string{"127.0.0.1"}}.Compile(), Active: map[string]bool{"graphql": active}}
	if err := eng.RunLocal(context.Background(), []types.Seed{seed}, b); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		if r.Entity.Key == srv.URL+"/graphql" {
			return r
		}
	}
	t.Fatal("no row for /graphql")
	return engine.MapEntry{}
}

// -graphql reads the schema of an endpoint a script names even when the
// script is read at the last wave: -depth limits the pages followed, not
// the technique asked of an endpoint found.
func TestGraphQLNamedByAScriptAtTheDepthLimitIsIntrospected(t *testing.T) {
	for _, depth := range []int{2, 3, 4} {
		t.Run(fmt.Sprint("depth ", depth), func(t *testing.T) {
			srv, posts, _ := scriptLab(t)
			row := mapFromRoot(t, srv, true, depth)
			if len(row.Ops) < 5 || posts.Load() == 0 || row.Coverage != "visited" {
				t.Errorf("-graphql: coverage %q, %d operations, %d POSTs", row.Coverage, len(row.Ops), posts.Load())
			}
		})
	}
}

// Without -graphql, -depth keeps the endpoint a script names at the last
// wave as it was: not asked, not POSTed.
func TestGraphQLNamedByAScriptAtTheDepthLimitIsNotAskedWithoutTheFlag(t *testing.T) {
	srv, posts, gets := scriptLab(t)
	row := mapFromRoot(t, srv, false, 2)
	if posts.Load() != 0 || gets.Load() != 0 || row.Coverage != "hint" || len(row.Ops) > 1 { // the script's own operation is the one
		t.Errorf("coverage %q, %d operations, %d GETs, %d POSTs", row.Coverage, len(row.Ops), gets.Load(), posts.Load())
	}
}
