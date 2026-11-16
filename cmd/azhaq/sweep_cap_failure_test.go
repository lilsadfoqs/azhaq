package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A request that failed before -max-requests is a failure row, as `fuzz`
// keeps it: `dirs` (calibrated or not) and `params` against a refused port,
// with the cap at 1 and above it. The cap with work left takes exit 4; a
// cap not reached leaves the run's own rule (exit 3: nothing answered).
func TestSweepsKeepTheFailureOfARequestSentBeforeTheCap(t *testing.T) {
	addr := deadAddr(t)
	for _, c := range []struct {
		name string
		args []string
		n    string
		exit int
	}{
		{"dirs", []string{"dirs", "-u", "http://" + addr + "/"}, "1", exitLimit},
		{"dirs", []string{"dirs", "-u", "http://" + addr + "/"}, "2", exitLimit},
		{"dirs", []string{"dirs", "-u", "http://" + addr + "/"}, "3", exitLimit},
		{"dirs-ac-off", []string{"dirs", "-ac=false", "-u", "http://" + addr + "/"}, "1", exitLimit},
		{"dirs-ac-off", []string{"dirs", "-ac=false", "-u", "http://" + addr + "/"}, "2", exitPartial},
		{"params", []string{"params", "-u", "http://" + addr + "/p"}, "1", exitLimit},
		{"params", []string{"params", "-u", "http://" + addr + "/p"}, "2", exitLimit},
	} {
		t.Run(c.name+" max-requests "+c.n, func(t *testing.T) {
			t.Chdir(t.TempDir())
			db := filepath.Join(t.TempDir(), "c.db")
			args := append(append([]string{}, c.args...), "-w", wlist(t, "one", "two", "three"), "-max-requests", c.n, "-allow", "127.0.0.1", "-ledger", "off", "-db", db)
			_, rep, code := runContract(t, args...)
			if code != c.exit {
				t.Errorf("exit %d, want %d: %+v", code, c.exit, rep)
			}
			if rep.Failures != 1 || len(rep.Failed) != 1 || rep.Failed[0].Error != "connection refused" {
				t.Errorf("failures %d, failed %+v, want one connection refused", rep.Failures, rep.Failed)
			}
			out, _, err := captureBoth(t, func() error { return run([]string{"query", "-db", db, "-failed"}) })
			if err != nil || !strings.Contains(out, "connection refused") {
				t.Errorf("query -failed: %q %v", out, err)
			}
		})
	}
}

// The same through `run -dirs`: the front page answers, every other request
// is cut off, and the cap stops the sweep's calibration or its first words.
func TestRunDirsKeepsTheFailureOfARequestSentBeforeTheCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<title>home</title>")
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer srv.Close()
	for _, n := range []string{"2", "3"} {
		t.Run("max-requests "+n, func(t *testing.T) {
			t.Chdir(t.TempDir())
			db := filepath.Join(t.TempDir(), "r.db")
			_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-dirs", wlist(t, "one", "two", "three"), "-no-takeover", "-no-favicon", "-no-tech",
				"-sources", "none", "-no-paths", "-max-requests", n, "-allow", "127.0.0.1", "-ledger", "off", "-db", db)
			if code != exitLimit {
				t.Errorf("exit %d, want %d: %+v", code, exitLimit, rep)
			}
			if rep.Failures < 1 || len(rep.Failed) < 1 || rep.Failed[0].Collector != "azhaq-dirs" {
				t.Errorf("failures %d, failed %+v, want the sweep's failure", rep.Failures, rep.Failed)
			}
		})
	}
}

// azhaq resume redoes a task the cap stopped, and the failure row the first
// pass kept goes with it: the same refusal is one failure after the resume,
// not two.
func TestResumeDoesNotCountAKeptFailureTwice(t *testing.T) {
	addr := deadAddr(t)
	for _, c := range []struct {
		name string
		args []string
	}{
		{"dirs", []string{"dirs", "-u", "http://" + addr + "/"}},
		{"params", []string{"params", "-u", "http://" + addr + "/p"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			db := filepath.Join(t.TempDir(), "r.db")
			args := append(append([]string{}, c.args...), "-w", wlist(t, "one", "two", "three"), "-max-requests", "1", "-allow", "127.0.0.1", "-ledger", "off", "-db", db)
			_, rep, code := runContract(t, args...)
			if code != exitLimit || rep.Failures != 1 {
				t.Fatalf("first pass: exit %d failures %d: %+v", code, rep.Failures, rep)
			}
			// Nothing listens still: with the cap off the task ends and the
			// refusal is counted once.
			_, rep, code = runContract(t, "resume", "-db", db, "-max-requests", "0")
			if code == exitLimit || rep.Failures != 1 || len(rep.Failed) != 1 || rep.Failed[0].Count != 1 {
				t.Errorf("after resume: exit %d failures %d failed %+v, want one refusal counted once", code, rep.Failures, rep.Failed)
			}
		})
	}
}

// A page that failed under the cap and answers after it is no failure once
// the resume has asked it again.
func TestResumeDropsAKeptFailureTheRedoDoesNotMeet(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "r.db")
	_, rep, code := runContract(t, "dirs", "-u", srv.URL+"/", "-w", wlist(t, "one", "two", "three"), "-max-requests", "1", "-allow", "127.0.0.1", "-ledger", "off", "-db", db)
	if code != exitLimit || rep.Failures != 1 {
		t.Fatalf("first pass: exit %d failures %d: %+v", code, rep.Failures, rep)
	}
	up.Store(true)
	_, rep, code = runContract(t, "resume", "-db", db, "-max-requests", "0")
	if code != exitOK || rep.Failures != 0 || len(rep.Failed) != 0 {
		t.Errorf("after resume: exit %d failures %d failed %+v, want none", code, rep.Failures, rep.Failed)
	}
}
