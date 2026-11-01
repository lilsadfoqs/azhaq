package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// A single-page app's server: every path answers the one shell, and a bundle
// names 6 directories of routes, perDir each.
func shellApp(t *testing.T, perDir int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var paths []string
	for _, w := range strings.Fields("users orders admin settings reports billing") {
		for i := 0; i < perDir; i++ {
			paths = append(paths, fmt.Sprintf("'/app/%s/view%d'", w, i))
		}
	}
	for i := 0; i < 5; i++ { // a directory of real pages, whose unknown paths are a 404
		paths = append(paths, fmt.Sprintf("'/svc/item%d'", i))
	}
	js := "var routes=[" + strings.Join(paths, ",") + "];\n"
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasPrefix(r.URL.Path, "/svc/") {
			if strings.HasPrefix(r.URL.Path, "/svc/item") {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"id":%q}`, r.URL.Path)
				return
			}
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/static/bundle.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, js)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>App</title></head><body><script src="/static/bundle.js"></script></body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func runShell(t *testing.T, srv *httptest.Server, extra ...string) (string, report) {
	t.Helper()
	args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-json", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
	if i := slices.Index(args, "-rows"); i >= 0 {
		args = slices.Delete(args, i, i+1)
	} else {
		args = append(args, "-quiet") // stdout is read after the command ends: keep it small
	}
	out, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	return out, lastReport(t, errOut)
}

// Once an origin has answered paths with the page every unknown path gets,
// run stops asking the paths scripts name on it: the rest are not requested,
// counted apart and said in a note, and the headline counts what is left.
func TestRunStopsAskingScriptPathsOnACatchAllOrigin(t *testing.T) {
	srv, hits := shellApp(t, 20)
	_, rep := runShell(t, srv)
	if n := hits.Load(); n > 100 { // 130 when every path is asked

		t.Errorf("%d requests reached the server for 120 script-named paths", n)
	}
	asked, held := rep.Counts["catchall"], rep.Counts["skipped"]
	if asked < 3 || held < 40 || asked+held != 120 {
		t.Errorf("counts %v: %d answered + %d not asked must be the 120 paths", rep.Counts, asked, held)
	}
	sum := 0
	for _, n := range rep.Counts {
		sum += n
	}
	if sum != rep.Stored || rep.Results != rep.Stored {
		t.Errorf("counts add up to %d, stored %d, results %d: %v", sum, rep.Stored, rep.Results, rep.Counts)
	}
	if rep.Counts["pages"] < 1 || rep.Counts["pages"]+rep.Counts["api"]+rep.Counts["scripts"] > 12 {
		t.Errorf("the catch-all paths are counted as pages: %v", rep.Counts)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, fmt.Sprintf("%d URLs that scripts name were not asked", held)) {
		t.Errorf("notes: %q", rep.Notes)
	}
	if rep.Counts["pages"]+rep.Counts["api"] < 6 {
		t.Errorf("the 5 real pages of /svc/ were held back with the catch-all ones: counts %v", rep.Counts)
	}
	if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Target, fmt.Sprintf("%d URLs of ", held)) {
		t.Errorf("skipped: %+v", rep.Skipped)
	}
}

// -catchall-after 0 asks every path: all 120 answers are catch-all rows,
// counted apart from the results.
func TestRunCatchAllAfterZeroAsksEveryPath(t *testing.T) {
	srv, hits := shellApp(t, 20)
	_, rep := runShell(t, srv, "-catchall-after", "0")
	if n := hits.Load(); n < 120 {
		t.Errorf("%d requests reached the server, want every path asked", n)
	}
	if rep.Counts["catchall"] != 120 || rep.Counts["skipped"] != 0 || rep.Results != rep.Stored {
		t.Errorf("results %d, counts %v", rep.Results, rep.Counts)
	}
}

// -no-catchall leaves the catch-all rows out of what is printed and of
// results; the summary still counts them (stored, counts, left_out). What
// run prints is what results counts, with it and without.
func TestRunNoCatchAllLeavesTheRowsOut(t *testing.T) {
	srv, _ := shellApp(t, 4)
	out, rep := runShell(t, srv, "-catchall-after", "0", "-no-catchall", "-rows")
	if strings.Contains(out, "/app/users/view") {
		t.Errorf("catch-all rows printed: %.300s", out)
	}
	if rep.Counts["catchall"] != 24 || rep.LeftOut != 24 || rep.Results != rep.Stored-rep.LeftOut {
		t.Errorf("results %d, stored %d, left out %d, counts %v", rep.Results, rep.Stored, rep.LeftOut, rep.Counts)
	}
	if n := len(lines(out)); n != rep.Results {
		t.Errorf("results %d, rows printed %d", rep.Results, n)
	}
	out, rep = runShell(t, srv, "-catchall-after", "0", "-rows")
	if !strings.Contains(out, "/app/users/view") || rep.LeftOut != 0 {
		t.Errorf("by default the rows are printed")
	}
	if n := len(lines(out)); n != rep.Results || rep.Results != rep.Stored {
		t.Errorf("results %d, stored %d, rows printed %d", rep.Results, rep.Stored, n)
	}
}

// In one directory the paths go one at a time until the origin has answered 3
// with its shell: exactly 3 are asked, whatever the load.
func TestRunCatchAllStopIsExactInOneDirectory(t *testing.T) {
	var paths []string
	for i := 0; i < 40; i++ {
		paths = append(paths, fmt.Sprintf("'/app/view%d'", i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/bundle.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, "var routes=["+strings.Join(paths, ",")+"];\n")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>App</title></head><body><script src="/static/bundle.js"></script></body></html>`)
	}))
	t.Cleanup(srv.Close)
	_, rep := runShell(t, srv)
	if rep.Counts["catchall"] != 3 || rep.Counts["skipped"] != 37 {
		t.Errorf("counts %v: want 3 asked and 37 held", rep.Counts)
	}
}
