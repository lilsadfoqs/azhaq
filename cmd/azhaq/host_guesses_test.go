package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A host's guesses are counted and capped: the 51 built-in paths of a sweep,
// asked of a site that answers each with a 404, are all sent without a cap and
// no more than the cap with one. The summary says which were not asked, and
// the run exits 4, as a limit that stopped work does.
func TestHostGuessesCapsTheSweepAndListsWhatWasNotAsked(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>Shop</title></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	run := func(extra ...string) (report, int64) {
		t.Helper()
		hits.Store(0)
		args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-tech", "-no-favicon", "-sources", "none", "-json", "-quiet",
			"-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
		_, errOut, _ := captureBoth(t, func() error { return cmdRun(args) })
		return lastReport(t, errOut), hits.Load()
	}
	full, all := run()
	if all < 51 || full.Exit != 0 {
		t.Fatalf("without a cap: %d requests, exit %d", all, full.Exit)
	}
	capped, n := run("-host-guesses", "20")
	if n > 20+3 || n < 10 { // the front page, and what it asks beside the guesses
		t.Errorf("-host-guesses 20: %d requests reached the host (%d without a cap)", n, all)
	}
	notes := strings.Join(capped.Notes, "\n")
	if !strings.Contains(notes, "reached -host-guesses 20") || !strings.Contains(notes, "azhaq-paths") || !strings.Contains(notes, "guesses were not sent") {
		t.Errorf("the notes do not say what was not asked:\n%s", notes)
	}
	if capped.Exit != exitLimit {
		t.Errorf("exit %d, want %d: a limit stopped work", capped.Exit, exitLimit)
	}
}

// A crawl that sweeps (-sweep) is held to the same cap: it sends no more
// guesses to a host than -host-guesses allows, and says what it did not ask.
func TestCrawlSweepIsHeldToHostGuesses(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>Shop</title></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	crawl := func(extra ...string) (string, int64) {
		hits.Store(0)
		_, errOut, _ := captureBoth(t, func() error {
			return cmdCrawl(append([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-json", "-sweep", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...))
		})
		return errOut, hits.Load()
	}
	if _, n := crawl(); n < 51 {
		t.Fatalf("a sweep sent %d requests, want the 51 paths and the page", n)
	}
	errOut, n := crawl("-host-guesses", "12")
	if n > 12+3 {
		t.Errorf("-host-guesses 12: %d requests reached the host", n)
	}
	if !strings.Contains(errOut, "reached -host-guesses 12") || !strings.Contains(errOut, "guesses were not sent") {
		t.Errorf("the summary does not say what was not asked: %s", errOut)
	}
}
