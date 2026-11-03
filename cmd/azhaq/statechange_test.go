package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// VAmPI's own description of GET /createdb ("creates and populates the
// database") produces its entry from the description alone: the pure
// read of the operations requests nothing.
func TestStateChangesFromVAmPIDescription(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"url": "http://vampi.test/createdb", "via": "openapi", "methods": []string{"GET"},
		"ops": []map[string]any{
			{"method": "GET", "description": "Creates and populates the database", "state_change": "create"},
			{"method": "POST", "description": "Deletes everything", "state_change": "delete"},
		},
	})
	payload2, _ := json.Marshal(map[string]any{
		"url": "http://vampi.test/users/v1", "via": "openapi", "methods": []string{"GET"},
		"ops": []map[string]any{{"method": "GET", "summary": "List users"}},
	})
	obs := []types.StoredObservation{
		{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "url", Payload: payload}},
		{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "url", Payload: payload2}},
	}
	got := stateChangesOfOps(obs)
	if len(got) != 1 {
		t.Fatalf("entries %+v, want only the GET /createdb", got)
	}
	e := got[0]
	if e.URL != "http://vampi.test/createdb" || e.Word != "create" || e.DenyPath != "-deny-path ^/createdb$" || !strings.Contains(e.Description, "populates") {
		t.Errorf("entry %+v", e)
	}
	if !strings.Contains(e.line(), "-deny-path ^/createdb$") {
		t.Errorf("line %q names no rule that keeps it out", e.line())
	}
}

// vampiApp serves a page, its API description (whose GET /createdb says
// it creates and populates the database) and the endpoints, and records
// every path asked.
func vampiApp(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>VAmPI</title><a href="/openapi.json">spec</a> <a href="/logout">out</a>`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.1","info":{"title":"VAmPI","version":"1"},"paths":{"/users/v1":{"get":{"summary":"List users"}},"/createdb":{"get":{"description":"Creates and populates the database"}}}}`)
		case "/users/v1", "/createdb", "/logout":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func stateURLs(rep report) []string {
	var out []string
	for _, e := range rep.StateChanging {
		out = append(out, e.URL)
	}
	return out
}

// A plan names the state-changing GET among its targets before any
// request: the server is asked nothing, and the entry names the word
// and the deny rule that would keep it out.
func TestPlanNamesStateChangingGETBeforeAnyRequest(t *testing.T) {
	srv, seen := vampiApp(t)
	p := planJSON(t, "-url", srv.URL+"/createdb", "-sources", "none", "-depth", "0")
	if got := seen(); len(got) != 0 {
		t.Fatalf("a plan sent %v", got)
	}
	if len(p.StateChanging) != 1 || p.StateChanging[0].URL != srv.URL+"/createdb" || p.StateChanging[0].DenyPath != "-deny-path ^/createdb$" {
		t.Fatalf("state_changing %+v", p.StateChanging)
	}
	out, _, err := captureBoth(t, func() error {
		return cmdPlan([]string{"-url", srv.URL + "/createdb", "-sources", "none", "-depth", "0"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "requests that may change state") || !strings.Contains(out, "/createdb") || !strings.Contains(out, "-deny-path ^/createdb$") {
		t.Errorf("the text plan does not name it:\n%s", out)
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("a plan sent %v", got)
	}
}

// A run names them too: among its targets before anything is sent, and
// the ones its API description and links name in its summary. With a
// deny rule for /createdb, the proxy (the recording server) is asked
// for it zero times and it is no longer listed as sent.
func TestRunNamesStateChangingGETsAndDenyKeepsThemOut(t *testing.T) {
	srv, seen := vampiApp(t)

	// The target itself: named, and still sent (the list informs).
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/createdb", "-sources", "none", "-depth", "0", "-no-paths", "-quiet", "-json", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if got := stateURLs(rep); len(got) != 1 || got[0] != srv.URL+"/createdb" {
		t.Errorf("state_changing %v\n%s", got, errOut)
	}
	if !slices.Contains(seen(), "/createdb") {
		t.Errorf("naming it withheld it: asked %v", seen())
	}

	// Found on the way: the description's /createdb and the /logout link.
	srv2, seen2 := vampiApp(t)
	_, errOut, err = captureBoth(t, func() error {
		return run([]string{"run", "-url", srv2.URL + "/", "-sources", "none", "-quiet", "-json", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep = lastReport(t, errOut)
	got := stateURLs(rep)
	if !slices.Contains(got, srv2.URL+"/createdb") || !slices.Contains(got, srv2.URL+"/logout") {
		t.Errorf("state_changing %v\n%s", got, errOut)
	}
	var created *stateChangeEntry
	for i := range rep.StateChanging {
		if rep.StateChanging[i].URL == srv2.URL+"/createdb" {
			created = &rep.StateChanging[i]
		}
	}
	if created == nil || created.Description == "" || created.DenyPath != "-deny-path ^/createdb$" {
		t.Errorf("the description's entry %+v", created)
	}
	if !slices.Contains(seen2(), "/createdb") || !slices.Contains(seen2(), "/logout") {
		t.Errorf("asked %v", seen2())
	}

	// The deny rule the list names: zero such requests at the server.
	srv3, seen3 := vampiApp(t)
	_, errOut, err = captureBoth(t, func() error {
		return run([]string{"run", "-url", srv3.URL + "/", "-sources", "none", "-deny-path", `^/createdb$`, "-quiet", "-json", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if slices.Contains(seen3(), "/createdb") {
		t.Errorf("the denied GET was asked: %v", seen3())
	}
	rep = lastReport(t, errOut)
	if slices.Contains(stateURLs(rep), srv3.URL+"/createdb") {
		t.Errorf("a kept-out GET is listed as sent: %v", stateURLs(rep))
	}
	if len(skippedFor(rep, "-deny-path ^/createdb$")) == 0 {
		t.Errorf("the kept-out GET is not listed as skipped: %+v", rep.Skipped)
	}
}
