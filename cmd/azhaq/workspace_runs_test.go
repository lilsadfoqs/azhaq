package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A workspace keeps every run: a later run into it adds to it, and show,
// query and diff read each run by its run_id.
func TestWorkspaceKeepsEarlierRuns(t *testing.T) {
	site := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><title>%s</title>", name)
		}))
	}
	one, two := site("one"), site("two")
	t.Cleanup(one.Close)
	t.Cleanup(two.Close)
	t.Chdir(t.TempDir())
	_, r1, code := runContract(t, "run", "-url", one.URL+"/", "-sources", "none", "-no-paths", "-db", "w.db")
	if code != exitOK {
		t.Fatalf("first run exit %d: %+v", code, r1.Failed)
	}
	_, r2, code := runContract(t, "run", "-url", two.URL+"/", "-sources", "none", "-no-paths", "-db", "w.db")
	if code != exitOK {
		t.Fatalf("second run exit %d: %+v", code, r2.Failed)
	}
	if r1.RunID == "" || r1.RunID == r2.RunID {
		t.Fatalf("run ids %q and %q", r1.RunID, r2.RunID)
	}
	if !strings.Contains(strings.Join(r2.Notes, "\n"), "holds 2 runs; this one is "+r2.RunID) {
		t.Errorf("the second summary does not say the workspace holds the first run: %q", r2.Notes)
	}

	read := func(args ...string) (string, int) {
		out, _, err := captureBoth(t, func() error { return run(args) })
		return out, exitCode(err)
	}
	// The runs the workspace holds.
	out, code := read("query", "-db", "w.db", "-runs")
	if code != exitOK || !strings.Contains(out, r1.RunID) || !strings.Contains(out, r2.RunID) {
		t.Errorf("query -runs (exit %d) does not list both runs:\n%s", code, out)
	}

	// show reads the first run's page by -run, and finds it without -run too.
	out, code = read("show", "-db", "w.db", "-run", r1.RunID[:8], one.URL+"/")
	if code != exitOK || !strings.Contains(out, "title=one") {
		t.Errorf("show -run: exit %d\n%s", code, out)
	}
	if _, code = read("show", "-db", "w.db", "-run", r2.RunID, one.URL+"/"); code == exitOK {
		t.Error("the second run did not see the first run's page, yet show -run named it and found it")
	}
	out, code = read("show", "-db", "w.db", one.URL+"/")
	if code != exitOK || !strings.Contains(out, "title=one") {
		t.Errorf("show without -run does not find the earlier run's page: exit %d\n%s", code, out)
	}

	out, code = read("show", "-db", "w.db", "-json", one.URL+"/")
	if code != exitOK || !strings.Contains(out, `"run":"`+r1.RunID+`"`) {
		t.Errorf("show -json does not name the run it read (%s): exit %d\n%s", r1.RunID, code, out)
	}

	// query reads each run's rows.
	out, _ = read("query", "-db", "w.db", "-run", r1.RunID, "-type", "URL")
	if !strings.Contains(out, one.URL) || strings.Contains(out, two.URL) {
		t.Errorf("query -run of the first run:\n%s", out)
	}
	out, _ = read("query", "-db", "w.db", "-type", "URL")
	if !strings.Contains(out, two.URL) || strings.Contains(out, one.URL) {
		t.Errorf("query of the newest run:\n%s", out)
	}

	// diff compares a run with the one before it; the first has none.
	out, code = read("diff", "-db", "w.db", "-run", r2.RunID)
	if code != exitOK || !strings.Contains(out, two.URL) {
		t.Errorf("diff -run of the second run (exit %d):\n%s", code, out)
	}
	if _, code = read("diff", "-db", "w.db", "-run", r1.RunID); code == exitOK {
		t.Error("diff -run of the first run compared it with nothing and exited 0")
	}
}
