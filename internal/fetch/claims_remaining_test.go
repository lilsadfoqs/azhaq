package fetch

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// An origin gets a control request for 24 directories; beyond them the
// nearest directory above that was asked stands for the control, and the
// path's own answer decides, not its name.
func TestCatchAllAsksAControlForAtMost24DirectoriesAndTheNearestAboveStandsForTheRest(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	var mu sync.Mutex
	probes := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ProbeToken()) {
			mu.Lock()
			probes[r.URL.Path]++
			mu.Unlock()
		}
		if r.URL.Path == "/d3/real" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":[1,2,3]}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/d") || strings.HasPrefix(r.URL.Path, "/zz/") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<title>Shell</title><app-root></app-root>`)
	}))
	t.Cleanup(srv.Close)
	if !catchAll(t, srv, "/about") {
		t.Fatal("the root's shell is not the catch-all")
	}
	for i := 0; i < 23; i++ {
		if !catchAll(t, srv, fmt.Sprintf("/d%d/x", i)) {
			t.Errorf("/d%d/x answers as an unknown path there does", i)
		}
	}
	mu.Lock()
	n := len(probes)
	mu.Unlock()
	if n != 24 {
		t.Fatalf("%d directories got a control, want 24 (the root and 23)", n)
	}
	// The 25th directory and beyond: no control of their own.
	if !catchAll(t, srv, "/d1/deep/x") {
		t.Error("/d1/deep/x: the nearest directory above, /d1/, stands for the control, and it answers so")
	}
	if catchAll(t, srv, "/zz/x") {
		t.Error("/zz/x: its nearest directory above is the root, whose control is the shell: a soft 404 in JSON is not that page")
	}
	if !catchAll(t, srv, "/d4/deep/y") || catchAll(t, srv, "/d3/real") {
		t.Error("a path's own answer decides: /d3/real answers for itself")
	}
	mu.Lock()
	n = len(probes)
	mu.Unlock()
	if n != 24 {
		t.Errorf("%d directories got a control after the others, want 24 still", n)
	}
}
