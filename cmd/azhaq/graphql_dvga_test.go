package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// dvga is the shape of DVGA's root: a page that links the GraphiQL page, a
// GraphQL endpoint at /graphql that reads its schema by introspection, and a
// /graphiql page that answers every POST the same way (400), whatever the
// query, and validates the queries introspection is not.
func dvga(t *testing.T) (srv *httptest.Server, graphqlPosts, ideSent *atomic.Int32) {
	t.Helper()
	graphqlPosts, ideSent = new(atomic.Int32), new(atomic.Int32)
	const schema = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,
"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"pastes"},{"name":"me"}]},
{"name":"Mutation","kind":"OBJECT","fields":[{"name":"createPaste"}]},
{"name":"Paste","kind":"OBJECT","fields":[{"name":"title"}]},
{"name":"String","kind":"SCALAR","fields":null}]}}}`
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><head><title>Damn Vulnerable GraphQL Application</title></head><body><a href="/graphiql">GraphiQL</a></body></html>`)
		case r.URL.Path == "/graphiql" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>GraphiQL</title><script src="/static/graphiql.min.js"></script></html>`)
		case r.URL.Path == "/graphiql":
			ideSent.Add(1)
			var q struct{ Query string }
			_ = json.NewDecoder(r.Body).Decode(&q)
			w.WriteHeader(http.StatusBadRequest)
			if strings.Contains(q.Query, "__schema") {
				io.WriteString(w, `{"errors":[{"message":"GraphiQL Access Rejected"}]}`)
				return
			}
			var errs []map[string]string
			for _, f := range strings.Fields(strings.Trim(strings.SplitN(q.Query, "{", 2)[1], " }")) {
				if f != "me" && f != "pastes" {
					errs = append(errs, map[string]string{"message": `Cannot query field "` + f + `" on type "Query".`})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			graphqlPosts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, schema)
		case r.URL.Path == "/graphql":
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":[{"message":"Must provide query string."}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, graphqlPosts, ideSent
}

// Pointed at the root, the run reads the endpoint's schema within a small
// budget: a page that refuses introspection the same way twice gets two POSTs
// and no more, is named in the summary, and does not spend the budget the
// endpoint's schema needs.
func TestGraphQLRecoveryDoesNotSpendTheBudgetOnARefusingPage(t *testing.T) {
	srv, graphqlPosts, ideSent := dvga(t)
	args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-graphql", "-no-tech", "-no-favicon", "-sources", "none",
		"-max-requests", "90", "-json", "-quiet", "-db", filepath.Join(t.TempDir(), "w.db")}
	_, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if n := graphqlPosts.Load(); n != 1 {
		t.Errorf("the endpoint's schema took %d POSTs, want its introspection read once (the budget ran out first)", n)
	}
	if n := ideSent.Load(); n > 2 {
		t.Errorf("the page that refuses was sent %d POSTs, want at most 2", n)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "/graphiql: refused the schema query twice the same way (400") {
		t.Errorf("the summary does not name the dropped page:\n%s", notes)
	}
	if rep.Stopped != "" || rep.Exit != 0 {
		t.Errorf("the budget stopped the run: exit %d, stopped %q", rep.Exit, rep.Stopped)
	}
}
