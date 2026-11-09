package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/collectors/rendercol"
	"github.com/lilsadfoqs/azhaq/types"
)

func TestInteractNotRunSaysWhy(t *testing.T) {
	clicked := []types.StoredObservation{{Observation: types.Observation{Collector: rendercol.Name, Kind: "interact"}}}
	failed := []types.StoredObservation{{Observation: types.Observation{Collector: rendercol.Name, Kind: "error"}}}
	for _, tc := range []struct {
		name    string
		obs     []types.StoredObservation
		stopped string
		want    string
	}{
		{"clicked", clicked, "", ""},
		{"clicked, then stopped", clicked, "the request budget of 20 is spent", ""},
		{"budget", nil, "the request budget of 20 is spent in the web map, 7 tasks known and not done (the cap holds for each run)", "-interact did not run: no page was clicked: the run stopped first (the request budget of 20 is spent in the web map, 7 tasks known and not done)"},
		{"time", nil, "-timeout 30s reached with 3 tasks known and not done", "the run stopped first (-timeout 30s reached"},
		{"chrome failed", failed, "", "1 page Chrome tried to load failed"},
		{"no page", nil, "", "Chrome loaded no page"},
	} {
		if got := interactNotRun(tc.obs, tc.stopped); !strings.Contains(got, tc.want) || (tc.want == "") != (got == "") {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// -interact that cannot run says so in the summary: the budget is spent in
// the map stage, before a page is clicked, and the run exits 4.
func TestCrawlInteractThatDidNotRunSaysSo(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		for i := 1; i <= 12; i++ {
			fmt.Fprintf(&b, `<a href="%s/%d">p%d</a> `, strings.TrimSuffix(r.URL.Path, "/"), i, i)
		}
		fmt.Fprintf(w, `<html><title>t</title><body>%s<button>go</button></body></html>`, b.String())
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "1", "-browser", "-interact", "-interact-clicks", "5",
		"-max-requests", "3", "-no-map-guess", "-db", "c.db", "-allow", "127.0.0.1", "-json")
	if code != exitLimit {
		t.Fatalf("exit %d, want %d\n%s", code, exitLimit, errOut)
	}
	if !strings.Contains(errOut, "-interact did not run: no page was clicked: the run stopped first (the request budget of 3 is spent") {
		t.Errorf("the summary does not say -interact did not run:\n%s", errOut)
	}
}
