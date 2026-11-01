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
	"github.com/lilsadfoqs/azhaq/internal/collectors/apicol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/gqlcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// An API description at a well-known path is read from a root seed at any
// -depth: the guess is of the target itself, not a step away from it.
func TestRootSeedReadsAnAPIDescriptionAtDepthOne(t *testing.T) {
	for _, depth := range []int{1, 2, 4} {
		t.Run(fmt.Sprint("depth ", depth), func(t *testing.T) {
			fetch.Reset()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, "<title>VAmPI</title>")
				case "/openapi.json":
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"openapi":"3.0.1","info":{"title":"VAmPI","version":"1"},"paths":{"/users/v1":{"get":{}},"/books/v1":{"get":{},"post":{}}}}`)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)
			st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			cat := catalog.New()
			httpcol.Register(cat, srv.Client())
			pathscol.Register(cat, srv.Client())
			apicol.Register(cat, srv.Client())
			eng := &engine.Engine{Cat: cat, Store: st}
			seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}
			if err := eng.RunLocal(context.Background(), []types.Seed{seed}, engine.Budgets{MaxDepth: depth, MaxItems: 64, Scope: scope.Rules{}.Compile()}); err != nil {
				t.Fatal(err)
			}
			ents, _ := st.Entities()
			obs, _ := st.Observations()
			ops := map[string]string{}
			for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
				ops[strings.TrimPrefix(r.Entity.Key, srv.URL)] = r.Evidence
			}
			if ops["/users/v1"] != "described" || ops["/books/v1"] != "described" {
				t.Errorf("the description's operations are not in the map: %v", ops)
			}
		})
	}
}

// graphqlLab answers GET at /graphql with refuse, and a POST that asks for
// the schema with the introspection fixture. posts counts the POSTs.
func graphqlLab(t *testing.T, refuse func(w http.ResponseWriter)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	fixture, err := os.ReadFile("../internal/gqlschema/testdata/introspection.json")
	if err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<title>lab</title>")
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
			refuse(w)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

func mapGraphQL(t *testing.T, srv *httptest.Server, active bool, depth int) engine.MapEntry {
	t.Helper()
	fetch.Reset()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cat := catalog.New()
	httpcol.Register(cat, srv.Client())
	pathscol.Register(cat, srv.Client())
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

// -graphql finds the endpoint from a root seed and reads its schema by
// introspection, whether the GET it is asked first is answered as GraphQL
// does (400, no query) or refused (500 and 405, the endpoint takes POST
// only), and at -depth 1. Without -graphql the endpoint is named and
// nothing is POSTed.
func TestRootSeedFindsGraphQLAndIntrospects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refuse func(w http.ResponseWriter)
	}{
		{"missing query", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"errors":[{"message":"Must provide query string."}]}`)
		}},
		{"500 post only", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error 500 java.lang.UnsupportedOperationException: GraphQL only supports POST method")
		}},
		{"405", func(w http.ResponseWriter) {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, posts := graphqlLab(t, tc.refuse)
			row := mapGraphQL(t, srv, true, 1)
			if row.Role != "api" && row.Role != "graphql" || len(row.Ops) < 5 || posts.Load() == 0 {
				t.Errorf("-graphql: role %q, %d operations, %d POSTs", row.Role, len(row.Ops), posts.Load())
			}
			if !strings.Contains(row.Proof, "exposed_by="+srv.URL+"/") {
				t.Errorf("the row does not say which URL exposed it: %q", row.Proof)
			}
			srv2, posts2 := graphqlLab(t, tc.refuse)
			plain := mapGraphQL(t, srv2, false, 1)
			if plain.Status == 0 || len(plain.Ops) != 0 || posts2.Load() != 0 {
				t.Errorf("without -graphql: status %d, %d operations, %d POSTs", plain.Status, len(plain.Ops), posts2.Load())
			}
		})
	}
}
