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

// An operation is named by its path, operationId or summary: the pure read
// of the operations requests nothing, and a description of the app or of an
// operation ("the app was created") names nothing.
func TestStateChangesOfOperationsReadTheNameNotProse(t *testing.T) {
	obs := func(url, path string, ops ...map[string]any) types.StoredObservation {
		payload, _ := json.Marshal(map[string]any{"url": url, "path": path, "via": "openapi", "methods": []string{"GET"}, "ops": ops})
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-openapi", Kind: "url", Payload: payload}}
	}
	got := stateChangesOfOps([]types.StoredObservation{
		obs("http://vampi.test/createdb", "/createdb", map[string]any{"method": "GET", "description": "Creates and populates the database"}),
		obs("http://vampi.test/books/v1", "/books/v1", map[string]any{"method": "GET", "operation_id": "deleteBooks"}),
		obs("http://vampi.test/users/v1/reset", "/users/v1/x", map[string]any{"method": "GET", "summary": "Resets a password"}),
		obs("http://vampi.test/", "/", map[string]any{"method": "GET", "operation_id": "home", "summary": "VAmPI home", "description": "VAmPI was created as a vulnerable API"}),
		obs("http://vampi.test/users/v1", "/users/v1", map[string]any{"method": "GET", "summary": "List users"}, map[string]any{"method": "POST", "summary": "Deletes everything"}),
	})
	want := map[string]string{
		"http://vampi.test/createdb":       "createdb",
		"http://vampi.test/books/v1":       "delete",
		"http://vampi.test/users/v1/reset": "reset",
	}
	if len(got) != len(want) {
		t.Fatalf("entries %+v, want only %v", got, want)
	}
	for _, e := range got {
		if want[e.URL] != e.Word {
			t.Errorf("entry %+v, want word %q", e, want[e.URL])
		}
		if !strings.Contains(e.line(), "-deny-path") && e.Status != "" {
			t.Errorf("line %q", e.line())
		}
	}
	for _, e := range got {
		switch e.URL {
		case "http://vampi.test/createdb":
			if e.Source != "its path" {
				t.Errorf("source %q", e.Source)
			}
		case "http://vampi.test/books/v1":
			if !strings.Contains(e.Source, "operationId deleteBooks") {
				t.Errorf("source %q", e.Source)
			}
		case "http://vampi.test/users/v1/reset":
			if e.Description != "Resets a password" {
				t.Errorf("description %q", e.Description)
			}
		}
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

// A run names the ones among its targets before anything is sent and sends
// them (the user gave them); the ones it finds on the way (the description's
// /createdb, the /logout link) are held back and named as held. With a deny
// rule for /createdb, the server is asked for it zero times and it is listed
// as skipped for the rule, not as held.
func TestRunNamesStateChangingGETsAndDenyKeepsThemOut(t *testing.T) {
	srv, seen := vampiApp(t)

	// The target itself: named, and sent, because the user gave it.
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/createdb", "-sources", "none", "-depth", "0", "-no-paths", "-quiet", "-json", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if got := stateURLs(rep); len(got) != 1 || got[0] != srv.URL+"/createdb" || rep.StateChanging[0].Status != stateSent {
		t.Errorf("state_changing %v\n%s", got, errOut)
	}
	if !slices.Contains(seen(), "/createdb") {
		t.Errorf("a target of the user's was withheld: asked %v", seen())
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
	for _, e := range rep.StateChanging {
		if e.Status != stateHeld {
			t.Errorf("%s found on the way is %q, want held back", e.URL, e.Status)
		}
	}
	if slices.Contains(seen2(), "/createdb") || slices.Contains(seen2(), "/logout") {
		t.Errorf("a GET found on the way that names a state change was asked: %v", seen2())
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
		t.Errorf("a kept-out GET is listed: %v", stateURLs(rep))
	}
	if len(skippedFor(rep, "-deny-path ^/createdb$")) == 0 {
		t.Errorf("the kept-out GET is not listed as skipped: %+v", rep.Skipped)
	}
}
