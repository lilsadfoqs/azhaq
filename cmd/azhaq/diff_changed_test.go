package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Two runs of an app that differ by a method on one route and a field on
// another: diff counts both as changed, and agrees with watch on the same
// two runs.
func TestDiffCountsRoutesWhoseMethodsOrFieldsChanged(t *testing.T) {
	var mu sync.Mutex
	v2 := false
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><title>app</title><script src="/main.js"></script></html>`))
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			body := `{name: "a"}`
			js := `fetch("/api/orders/list");`
			if v2 {
				body = `{name: "a", email: "b"}`
				js = `fetch("/api/orders/list"); fetch("/api/orders/list", {method: "DELETE"});`
			}
			w.Write([]byte(js + `fetch("/api/profile", {method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify(` + body + `)});`))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	db := filepath.Join(t.TempDir(), "ws.db")
	watch := func() changes {
		out := capture(t, func() error {
			return cmdWatch([]string{"-db", db, "-json", "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
		})
		var ch changes
		if err := json.Unmarshal([]byte(out), &ch); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		return ch
	}
	watch()
	mu.Lock()
	v2 = true
	mu.Unlock()
	ch := watch()
	want := 0
	for _, r := range ch.Routes {
		if r.Kind == "methods" || r.Kind == "fields" {
			want++
		}
	}
	if want != 2 {
		t.Fatalf("watch should report a method change and a field change: %+v", ch.Routes)
	}

	out, errOut, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	var sum map[string]any
	rows := 0
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		switch m["kind"] {
		case "summary":
			sum = m
		case "changed":
			rows++
			if m["what"] != "route" || (m["change"] != "methods" && m["change"] != "fields") || m["route"] == "" {
				t.Errorf("changed row %v", m)
			}
		}
	}
	if sum == nil || sum["changed"] != float64(want) || rows != want {
		t.Fatalf("summary %v, %d changed rows; watch reports %d\n%s", sum, rows, want, out)
	}
	text, _, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db}) })
	if err != nil || !strings.Contains(text, "changed=2") || !strings.Contains(text, "~ /api/orders/list: +DELETE") || !strings.Contains(text, "~ PUT /api/profile: +email") {
		t.Fatalf("%v\n%s", err, text)
	}
}
