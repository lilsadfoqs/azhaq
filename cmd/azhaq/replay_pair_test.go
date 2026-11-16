package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
)

// recordPair makes a run pair the way the parity run keeps one (pairs=1): a
// run, then watch's second run into the same workspace, then the export of
// each run. It returns the folder that holds export-run1.jsonl and
// export-run2.jsonl.
func recordPair(t *testing.T, site *httptest.Server, between func()) string {
	t.Helper()
	u, _ := url.Parse(site.URL)
	flags := []string{"-url", site.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-skip", "azhaq-paths", "-ports", u.Port(), "-ledger", "off"}
	dir := t.TempDir()
	db := filepath.Join(dir, "workspace.db")
	if _, _, err := captureBoth(t, func() error { return run(append(append([]string{"run"}, flags...), "-db", db, "-quiet")) }); err != nil {
		t.Fatal(err)
	}
	between()
	if _, _, err := captureBoth(t, func() error { return cmdWatch(append([]string{"-db", db, "-json", "--"}, flags...)) }); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := st.Runs()
	st.Close()
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs %v: %v", runs, err)
	}
	pair := filepath.Join(dir, "pair")
	if err := os.MkdirAll(pair, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, r := range runs {
		out, _, err := captureBoth(t, func() error { return run([]string{"export", "-db", db, "-format", "jsonl", "-run", r.ID}) })
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pair, "export-run"+string(rune('1'+i))+".jsonl"), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func fixtureSite(title *atomic.Value) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "fixture/1.0")
			_, _ = w.Write([]byte(`<html><title>` + title.Load().(string) + `</title><a href="/a">a</a></html>`))
		case "/a":
			_, _ = w.Write([]byte(`<html><title>a</title></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// The pair path end to end on a local server: two real runs, their exports,
// and the comparison the corpus test makes (#491). No docker, no lab network.
func TestReplayPairFixtureUnchangedTargetReportsNothing(t *testing.T) {
	var title atomic.Value
	title.Store("site")
	site := fixtureSite(&title)
	defer site.Close()
	dir := recordPair(t, site, func() {})
	// The fixture holds the rows the readers care about, or it proves nothing.
	have := map[string]bool{}
	for _, r := range replayRows(t, filepath.Join(dir, "pair", "export-run2.jsonl")) {
		have[r.obs.Collector] = true
	}
	if !have["azhaq-ports"] || !have["azhaq-http"] || !have[""] {
		t.Fatalf("collectors of the second run's rows: %v", have)
	}
	checkPairs(t, dir)
}

// A page that changed between the runs is reported by the same check, so the
// check can fail: a test that cannot fail proves nothing.
func TestReplayPairFixtureNamesAChangedPage(t *testing.T) {
	var title atomic.Value
	title.Store("site")
	site := fixtureSite(&title)
	defer site.Close()
	dir := recordPair(t, site, func() { title.Store("another title") })
	pairs := replayPairs(dir)
	if len(pairs) != 1 {
		t.Fatalf("pairs %v", pairs)
	}
	for _, p := range pairs {
		watch, diff := pairProblems(t, replayRows(t, p[0]), replayRows(t, p[1]))
		if !strings.Contains(strings.Join(watch, "\n"), "another title") {
			t.Errorf("watch lines %q do not name the new title", watch)
		}
		if len(diff) == 0 {
			t.Errorf("diff reports nothing for a page whose title changed")
		}
	}
}
