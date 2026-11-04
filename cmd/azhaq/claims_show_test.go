package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
)

// show prints one entity with what found it, what it leads to and every
// observation the workspace holds for it.
func TestShowPrintsWhatFoundItWhatItLeadsToAndEveryObservation(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>home</title><script src="/app.js"></script><a href="/about">about</a></html>`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>about</title><a href="/">home</a></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/users")`)
		case "/api/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"users":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	db := filepath.Join(t.TempDir(), "w.db")
	cli(t, "run", "-url", site.URL+"/", "-allow", "127.0.0.1", "-db", db, "-quiet", "-no-paths")
	out, _, code := cli(t, "show", "-db", db, "-json", site.URL+"/about")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var shown struct {
		Row struct {
			Key     string   `json:"key"`
			FoundIn []string `json:"found_in"`
		} `json:"row"`
		Links []struct {
			Rel, Dir, Type, Key string
		} `json:"links"`
		Observations []struct {
			Collector string          `json:"collector"`
			Kind      string          `json:"kind"`
			Source    string          `json:"source"`
			Payload   json.RawMessage `json:"payload"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(out), &shown); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if shown.Row.Key != site.URL+"/about" {
		t.Errorf("the row: %+v", shown.Row)
	}
	// What found it (a link in) and what it leads to (links out).
	var in, out2 bool
	for _, l := range shown.Links {
		in = in || l.Dir == "in" && l.Rel == "FOUND" && l.Key == site.URL+"/"
		out2 = out2 || l.Dir == "out"
	}
	if !in || !out2 {
		t.Errorf("links: %+v", shown.Links)
	}
	// A route a script names says where: found_in.
	api, _, _ := cli(t, "show", "-db", db, "-json", site.URL+"/api/users")
	var route struct {
		Row struct {
			FoundIn []any `json:"found_in"`
		} `json:"row"`
	}
	if err := json.Unmarshal([]byte(api), &route); err != nil || len(route.Row.FoundIn) == 0 || !strings.Contains(api, "/app.js") {
		t.Errorf("a route a script names: %v %s", err, api)
	}
	// Every observation the workspace holds for the entity is printed.
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if runs, err := st.Runs(); err == nil && len(runs) > 0 {
		st.UseRun(runs[len(runs)-1].ID)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	id := ""
	for _, e := range ents {
		if e.Key == site.URL+"/about" {
			id = e.ID
		}
	}
	held := 0
	for _, o := range obs {
		if o.EntityID != id {
			continue
		}
		held++
		found := false
		for _, s := range shown.Observations {
			found = found || s.Collector == o.Collector && s.Kind == o.Kind && s.Source == o.Source && string(s.Payload) == string(o.Payload)
		}
		if !found {
			t.Errorf("show leaves out the observation of %s (%s)", o.Collector, o.Kind)
		}
	}
	if held == 0 || len(shown.Observations) < held {
		t.Errorf("the workspace holds %d observations of the page, show prints %d", held, len(shown.Observations))
	}
	if host, _, code := cli(t, "show", "-db", db, "-json", "127.0.0.1"); code != exitOK || !strings.Contains(host, `"key":"127.0.0.1"`) {
		t.Errorf("a host: exit %d, %s", code, host)
	}
	if txt, _, _ := cli(t, "show", "-db", db, site.URL+"/about"); !strings.Contains(txt, "links\n") || !strings.Contains(txt, "observations\n") || strings.Count(txt, "\n  azhaq-") < held {
		t.Errorf("the text form:\n%s", txt)
	}
}
