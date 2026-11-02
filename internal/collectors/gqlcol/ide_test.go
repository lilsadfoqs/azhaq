package gqlcol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// ideServer has the real endpoint at /graphql and a GraphiQL page at
// /graphiql that refuses introspection but validates queries. onIDE sees
// the count of POSTs the page has had.
func ideServer(t *testing.T, onIDE func(n int)) (*httptest.Server, *atomic.Int32) {
	var idePosts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/graphiql" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><title>GraphiQL</title></html>`))
		case r.URL.Path == "/graphiql":
			n := int(idePosts.Add(1))
			var q struct{ Query string }
			_ = json.NewDecoder(r.Body).Decode(&q)
			w.WriteHeader(http.StatusBadRequest)
			if strings.Contains(q.Query, "__schema") {
				_, _ = w.Write([]byte(`{"errors":[{"message":"GraphiQL Access Rejected"}]}`))
				return
			}
			var errs []map[string]string
			for _, f := range strings.Fields(strings.Trim(strings.SplitN(q.Query, "{", 2)[1], " }")) {
				if f != "me" && f != "users" {
					errs = append(errs, map[string]string{"message": `Cannot query field "` + f + `" on type "Query".`})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
			if onIDE != nil {
				onIDE(n)
			}
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(schema))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &idePosts
}

// detect is the recognising stage on each path, which runs before the
// schema stage does.
func detect(t *testing.T, srv *httptest.Server, paths ...string) {
	t.Helper()
	for _, p := range paths {
		run(t, New(srv.Client()), srv.URL+p)
	}
}

// A GraphiQL page is not asked for a schema once the origin's endpoint gave
// it whole: no POST goes to the page, and the summary says so.
func TestIDEPageSkippedAfterTheOriginsSchema(t *testing.T) {
	fetch.Reset()
	srv, idePosts := ideServer(t, nil)
	s := NewSchema(srv.Client())
	detect(t, srv, "/graphql", "/graphiql")
	if got, _ := run(t, s, srv.URL+"/graphql"); got["introspection"] != true {
		t.Fatalf("the endpoint's schema: %v", got)
	}
	got, _ := run(t, s, srv.URL+"/graphiql")
	if got != nil || idePosts.Load() != 0 {
		t.Errorf("the IDE page was asked: %d POSTs, %v", idePosts.Load(), got)
	}
	var noted bool
	for _, n := range fetch.Notes() {
		noted = noted || strings.Contains(n, "/graphiql") && strings.Contains(n, "/graphql on the same origin gave it whole")
	}
	if !noted {
		t.Errorf("no note says the IDE page was left out: %v", fetch.Notes())
	}
}

// The origin's schema may be read while the page's recovery runs: it stops
// at the next document instead of spending its whole bound.
func TestIDERecoveryStopsWhenTheOriginsSchemaArrives(t *testing.T) {
	fetch.Reset()
	var srv *httptest.Server
	srv, idePosts := ideServer(t, func(n int) {
		if n == 3 {
			fetch.Learn(schemaFact(srv.URL+"/graphql"), srv.URL+"/graphql")
		}
	})
	detect(t, srv, "/graphiql")
	run(t, NewSchema(srv.Client()), srv.URL+"/graphiql")
	if n := idePosts.Load(); n > 4 {
		t.Errorf("%d POSTs to the IDE page after the origin's schema was known, want at most 4", n)
	}
}

// Alone on its origin, a page that validates queries is recovered in full.
func TestIDERecoveryWithoutAnotherEndpoint(t *testing.T) {
	fetch.Reset()
	srv, idePosts := ideServer(t, nil)
	detect(t, srv, "/graphiql")
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphiql")
	if got["recovered"] != "suggestions" || idePosts.Load() < 4 {
		t.Errorf("recovery of a lone IDE page: %d POSTs, %v", idePosts.Load(), got)
	}
}
