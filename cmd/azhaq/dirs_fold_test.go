package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A single-page app whose /api/* answers every unknown name with the same
// 500, beside two real routes, and a /priv/ that refuses everything alike.
func foldSPA(t *testing.T, asked *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if asked != nil {
			asked.Add(1)
		}
		p := r.URL.Path
		switch {
		case p == "/api/users":
			fmt.Fprint(w, `{"users":[1,2,3]}`)
		case p == "/api/items":
			fmt.Fprint(w, `{"items":["a"]}`)
		case strings.HasPrefix(p, "/api/"):
			w.WriteHeader(500)
			fmt.Fprint(w, "Error: Unexpected path")
		case strings.HasPrefix(p, "/priv/"):
			w.WriteHeader(403)
			fmt.Fprint(w, "Forbidden")
		default:
			fmt.Fprint(w, "<html><title>App</title><body>the same shell for every route</body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const foldWords = "api/users api/items api/notAPathXYZ api/foo api/bar priv/a priv/b priv/c nothing"

// dirs folds the hits of a directory that answer as the directory's control
// does into one line with their count and the control's URL; -json keeps
// every row, marked; the control is a request the summary counts, and results
// is what is listed.
func TestDirsFoldsACatchAllInsideADirectory(t *testing.T) {
	var asked atomic.Int64
	srv := foldSPA(t, &asked)
	wl := wlist(t, strings.Fields(foldWords)...)
	out, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "all", "-fc", "404", "-ledger", "off"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.Contains(out, srv.URL+"/api/users ") || !strings.Contains(out, srv.URL+"/api/items ") {
		t.Errorf("only the real routes are listed: %q", out)
	}
	if !strings.Contains(errOut, "folded catchall: 3 URLs of "+srv.URL+"/api/ answer as the control does: GET /api/") ||
		!strings.Contains(errOut, "folded catchall: 3 URLs of "+srv.URL+"/priv/ answer as the control does: GET /priv/") {
		t.Errorf("the folds are not in the summary:\n%s", errOut)
	}
	// 9 words, 4 calibration names and a control for /api/ and /priv/.
	if got := asked.Load(); got != 9+4+2 {
		t.Errorf("%d requests", got)
	}

	jsonOut, jsonErr, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "all", "-fc", "404", "-json", "-ledger", "off"})
	})
	if err != nil {
		t.Fatal(err)
	}
	marked, rows := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(jsonOut), "\n") {
		rows++
		if strings.Contains(line, `"fold":"catchall"`) {
			marked++
			if !strings.Contains(line, `"control":"`+srv.URL+`/`) {
				t.Errorf("a folded row names its control: %s", line)
			}
		}
	}
	rep := lastReport(t, jsonErr)
	if rows != 8 || marked != 6 || rep.Results != 2 || rep.Requests != 15 || len(rep.Folds) != 2 || rep.Folds[0].Count+rep.Folds[1].Count != 6 {
		t.Errorf("-json: %d rows, %d marked; summary results %d, requests %d, folds %+v", rows, marked, rep.Results, rep.Requests, rep.Folds)
	}
	if rep.Exit != 0 || rep.Failures != 0 {
		t.Errorf("a fold is not a failure: %+v", rep)
	}
}

// run -dirs folds the same rows in the map: its fold line names the controls,
// and the two real routes stay.
func TestRunDirsFoldsACatchAllInsideADirectory(t *testing.T) {
	srv := foldSPA(t, nil)
	wl := wlist(t, strings.Fields(foldWords)...)
	out, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-dirs", wl, "-no-paths", "-ledger", "off", "-db", t.TempDir() + "/r.db"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	for _, p := range []string{"/api/users", "/api/items"} {
		if !strings.Contains(out, srv.URL+p+" ") {
			t.Errorf("%s is listed: %s", p, out)
		}
	}
	for _, p := range []string{"/api/foo", "/api/bar", "/api/notAPathXYZ", "/priv/a"} {
		if strings.Contains(out, srv.URL+p+" ") {
			t.Errorf("%s is folded: %s", p, out)
		}
	}
	if !strings.Contains(out, "folded catchall: 6 URLs of "+srv.URL+" answer as the control does: GET /api/") || !strings.Contains(out, "GET /priv/") {
		t.Errorf("the fold line:\n%s", out)
	}
}

// Against ffuf -ac on the same stand-in (skipped when ffuf is not installed):
// ffuf lists the catch-all rows of /api/ and /priv/; dirs lists only what
// answers for itself, and every route ffuf lists that is real, dirs lists.
func TestDirsAgainstFfufAcOnACatchAllDirectory(t *testing.T) {
	ffuf, err := exec.LookPath("ffuf")
	if err != nil {
		if ffuf, err = filepath.Abs("../../.scratch/bin/ffuf"); err != nil {
			t.Skip("ffuf is not installed")
		}
		if _, err := os.Stat(ffuf); err != nil {
			t.Skip("ffuf is not installed")
		}
	}
	srv := foldSPA(t, nil)
	wl := wlist(t, strings.Fields(foldWords)...)
	raw, err := exec.Command(ffuf, "-u", srv.URL+"/FUZZ", "-w", wl, "-ac", "-mc", "all", "-s").Output()
	if err != nil {
		t.Skipf("ffuf: %v", err)
	}
	theirs := map[string]bool{}
	for _, l := range strings.Fields(string(raw)) {
		theirs[l] = true
	}
	out, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "all", "-silent", "-ledger", "off"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	ours := map[string]bool{}
	for _, l := range strings.Fields(out) {
		ours[strings.TrimPrefix(l, srv.URL+"/")] = true
	}
	if len(ours) != 2 || !ours["api/users"] || !ours["api/items"] {
		t.Errorf("dirs lists %v", ours)
	}
	catchAll := 0
	for w := range theirs {
		if strings.HasPrefix(w, "priv/") || strings.HasPrefix(w, "api/") && w != "api/users" && w != "api/items" {
			catchAll++
		}
	}
	t.Logf("ffuf -ac lists %d rows, %d of them catch-all; dirs lists %d", len(theirs), catchAll, len(ours))
	for _, w := range []string{"api/users", "api/items"} {
		if theirs[w] && !ours[w] {
			t.Errorf("ffuf lists the real route %s and dirs does not", w)
		}
	}
}
