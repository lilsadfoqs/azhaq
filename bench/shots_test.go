package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// shotFronts counts what reaches the page behind it, per run of each tool,
// and keeps the page's path, so that both tools are given the same address.
func TestShotFrontsCountPerRun(t *testing.T) {
	var got []string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer site.Close()
	f := &shotFronts{}
	defer f.close()
	front := f.front(site.URL + "/login")
	if !strings.HasSuffix(front, "/login") || strings.Contains(front, site.Listener.Addr().String()) {
		t.Fatalf("front %q does not stand for %s/login", front, site.URL)
	}
	hit := func(n int) {
		for range n {
			resp, err := http.Get(front)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
	for _, n := range []int{3, 5, 4} { // three runs of one tool
		f.begin("a")
		hit(n)
	}
	f.end("a")
	for _, n := range []int{2, 2, 9} {
		f.begin("b")
		hit(n)
	}
	f.end("b")
	if a, b := f.median("a"), f.median("b"); a != 4 || b != 2 {
		t.Errorf("medians %d and %d, want 4 and 2", a, b)
	}
	if len(got) != 25 || got[0] != "/login" {
		t.Errorf("the page got %d requests, first %q; want 25 and /login", len(got), got[:1])
	}
}

// The requests check holds azhaq to shotCostBar times the reference's and
// fails when the reference sent nothing: no requests is no reference.
func TestShotCostBar(t *testing.T) {
	for _, tc := range []struct {
		az, gw int
		pass   bool
	}{{10, 8, true}, {11, 9, true}, {12, 9, false}, {1, 1, true}, {5, 0, false}, {0, 0, false}} {
		rec.Checks = nil
		shotCost(&shotsRow{AzhaqRequests: tc.az, GowitnessRequests: tc.gw}, "azhaq shots vs gowitness scan")()
		if len(rec.Checks) != 1 || rec.Checks[0].Pass != tc.pass {
			t.Errorf("azhaq %d, gowitness %d: %+v, want pass %v", tc.az, tc.gw, rec.Checks, tc.pass)
		}
	}
	rec.Checks = nil
}
