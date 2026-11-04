package gqlcol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A schema over 8 MB is kept without its descriptions; one that is still
// over it is left out and its size is said.
func TestSchemaOver8MBIsKeptWithoutItsDescriptions(t *testing.T) {
	const mb = 1 << 20
	serve := func(types string) *httptest.Server {
		body := `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[` + types + `]}}}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"errors":[{"message":"Must provide query string."}]}`))
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	run1 := func(types string) map[string]any {
		fetch.Reset()
		srv := serve(types)
		got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
		return got
	}
	small := run1(`{"name":"Query","kind":"OBJECT","description":"the root","fields":[{"name":"me","description":"who"}]}`)
	if raw, _ := json.Marshal(small["schema"]); !strings.Contains(string(raw), "the root") {
		t.Errorf("a small schema loses its descriptions: %s", raw)
	}
	// 9 MB of descriptions: over 8 MB, and under it without them.
	fat := run1(`{"name":"Query","kind":"OBJECT","description":"` + strings.Repeat("d", 9*mb) + `","fields":[{"name":"me"}]}`)
	raw, _ := json.Marshal(fat["schema"])
	if len(raw) == 0 || len(raw) > 8*mb || strings.Contains(string(raw), "dddddddd") || fat["schema_bytes"] != nil || fmt.Sprint(fat["queries"]) != "[me]" {
		t.Errorf("a schema over 8 MB: %d bytes kept, schema_bytes %v, queries %v", len(raw), fat["schema_bytes"], fat["queries"])
	}
	// Still over without them: schema is left out, its size is said.
	huge := run1(`{"name":"Query","kind":"OBJECT","fields":[{"name":"me"}]},{"name":"` + strings.Repeat("n", 9*mb) + `","kind":"OBJECT","fields":[]}`)
	if huge["schema"] != nil || huge["schema_bytes"] == nil || fmt.Sprint(huge["queries"]) != "[me]" {
		t.Errorf("a schema still over 8 MB: schema %v, schema_bytes %v, queries %v", huge["schema"] != nil, huge["schema_bytes"], huge["queries"])
	}
}

// The built-in wordlist holds the verbs and nouns the page names, and parts
// of names are recombined pairwise and with an "All" infix.
func TestWordlistAndDerivedWords(t *testing.T) {
	have := map[string]bool{}
	for _, w := range deriveVerbs {
		have[w] = true
	}
	for _, w := range deriveNouns {
		have[w] = true
	}
	for _, w := range []string{"get", "list", "all", "create", "update", "delete", "import", "upload", "system", "health", "diagnostics", "user"} {
		if !have[w] {
			t.Errorf("the wordlist lacks %q", w)
		}
	}
	got := deriveWords([]string{"pastes"}, nil)
	for _, want := range []string{"deleteAllPastes", "deletePastes", "getAllPastes"} {
		if !slices.Contains(got, want) {
			t.Errorf("deriveWords(pastes) lacks %q", want)
		}
	}
	// At most 4000 words are made, taking the parts in alphabetical order.
	if len(got) != 4000 || slices.Contains(got, "updateAllPastes") {
		t.Errorf("%d words, updateAllPastes among them: %v", len(got), slices.Contains(got, "updateAllPastes"))
	}
	// A word of the user's own is recombined too.
	if got := deriveWords(nil, []string{"Aaa"}); !slices.Contains(got, "deleteAllAaa") || !slices.Contains(got, "aaaDelete") {
		t.Errorf("the -graphql-wordlist is not recombined")
	}
}

// A recovered schema is not the server's: it lacks the fields no word or
// suggestion reached and the types whose fields the errors did not name.
func TestRecoveredSchemaLacksWhatTheServerNeverSaid(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct{ Query string }
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q.Query, "__schema") {
			_, _ = w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
			return
		}
		// users has an object type the errors name; health is a scalar the
		// errors say nothing of; zzzAuditLog is a field nothing reaches.
		have := map[string]string{"users": "[UserObject]", "health": "", "zzzAuditLog": "AuditLogObject"}
		reachable := map[string]bool{"users": true, "health": true}
		var errs []map[string]string
		for _, f := range strings.Fields(strings.Trim(strings.SplitN(q.Query, "{", 2)[1], " }")) {
			switch {
			case !reachable[f]:
				errs = append(errs, map[string]string{"message": `Cannot query field "` + f + `" on type "Query".`})
			case have[f] != "":
				errs = append(errs, map[string]string{"message": `Field "` + f + `" of type "` + have[f] + `" must have a sub selection.`})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
	}))
	defer srv.Close()
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	sigs, _ := got["signatures"].(map[string]any)
	if got["recovered"] != "suggestions" || fmt.Sprint(got["queries"]) != "[health users]" || fmt.Sprint(got["types"]) != "[UserObject]" ||
		fmt.Sprint(sigs["queries"]) != "[health users: [UserObject]]" || got["complete"] != false {
		t.Errorf("recovered %v", got)
	}
}

// Recovery sends at most 96 documents to one endpoint, 48 for the query type
// and 48 for the mutation type, and every document carries a field no schema has.
func TestRecoverySendsAtMost96Documents(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	var queryDocs, mutationDocs, introspection, withoutPoison int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct{ Query string }
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q.Query, "__schema") {
			mu.Lock()
			introspection++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
			return
		}
		root, have := "Query", "users"
		mu.Lock()
		if strings.HasPrefix(q.Query, "mutation") {
			root, have = "Mutations", "createUser"
			mutationDocs++
		} else {
			queryDocs++
		}
		if !strings.Contains(q.Query, poison) {
			withoutPoison++
		}
		mu.Unlock()
		var errs []map[string]string
		for _, f := range strings.Fields(strings.Trim(strings.SplitN(q.Query, "{", 2)[1], " }")) {
			if f != have {
				errs = append(errs, map[string]string{"message": `Cannot query field "` + f + `" on type "` + root + `".`})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
	}))
	defer srv.Close()
	got, _ := run(t, NewSchema(srv.Client()), srv.URL+"/graphql")
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(got["queries"]) != "[users]" || fmt.Sprint(got["mutations"]) != "[createUser]" {
		t.Fatalf("recovered %v", got)
	}
	if queryDocs != 48 || mutationDocs != 48 || MaxRecoveryPOSTs != 96 || withoutPoison != 0 {
		t.Errorf("%d query documents and %d mutation documents (%d with no field no schema has), want 48 and 48 and none", queryDocs, mutationDocs, withoutPoison)
	}
}

// Two refusals are one gate when they carry the same error status and the
// same body, and the body names neither __schema nor introspection.
func TestRefusedAlikeNeedsTheSameStatusAndBodyThatNamesNeitherSchemaNorIntrospection(t *testing.T) {
	body := []byte(`{"errors":[{"message":"GraphiQL Access Rejected"}]}`)
	for _, c := range []struct {
		name   string
		s1, s2 int
		b1, b2 []byte
		want   bool
	}{
		{"the same refusal", 400, 400, body, body, true},
		{"the same, with space around", 400, 400, body, append([]byte("\n"), body...), true},
		{"another status", 400, 403, body, body, false},
		{"another body", 400, 400, body, []byte(`{"errors":[{"message":"nope"}]}`), false},
		{"not an error status", 200, 200, body, body, false},
		{"names __schema", 400, 400, []byte(`{"errors":[{"message":"no __schema here"}]}`), []byte(`{"errors":[{"message":"no __schema here"}]}`), false},
		{"names introspection", 400, 400, []byte(`Introspection is off`), []byte(`Introspection is off`), false},
		{"says Cannot query field", 400, 400, []byte(`Cannot query field "x"`), []byte(`Cannot query field "x"`), false},
	} {
		if got := refusedAlike(c.s1, c.b1, c.s2, c.b2); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
