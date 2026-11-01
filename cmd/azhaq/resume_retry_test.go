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

// Two requests that ended in a closed connection are listed as retryable:
// resume says so instead of "every run finished", and -retry-failed asks
// only them again and says how many still fail.
func TestResumeRetriesTheFailedTargetsTheSummaryCallsRetryable(t *testing.T) {
	var healed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, "<title>home</title><a href='/boom'>b</a><a href='/swagger-ui'>s</a>")
		case healed.Load():
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
		default:
			conn, buf, _ := w.(http.Hijacker).Hijack()
			if r.URL.Path == "/swagger-ui" {
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n<html>partial")
				_ = buf.Flush()
			}
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "e.db")
	flags := []string{"-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths", "-no-favicon", "-no-tech", "-db", db, "-ledger", "off", "-json"}
	_, errOut, err := captureBoth(t, func() error { return run(append([]string{"run", "-url", srv.URL + "/"}, flags...)) })
	rep := lastReport(t, errOut)
	if exitCode(err) != exitPartial || len(rep.Failed) == 0 || !rep.Failed[0].Retryable {
		t.Fatalf("first run: exit %d, failed %+v\n%s", exitCode(err), rep.Failed, errOut)
	}
	// Nothing is left to run, and the failures are retryable: say it.
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-json"}) })
	if err == nil || strings.Contains(err.Error(), "every run finished") || !strings.Contains(err.Error(), "-retry-failed") || !strings.Contains(err.Error(), "retryable") {
		t.Fatalf("resume with only retryable failures: %v", err)
	}
	// Asked again while the server still fails: the summary says so, exit 3.
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	rep = lastReport(t, errOut)
	if exitCode(err) != exitPartial || !strings.Contains(strings.Join(rep.Notes, "\n"), "-retry-failed: 2 failed targets asked again, 2 still fail") {
		t.Fatalf("a retry that fails again: exit %d, notes %v, failed %+v", exitCode(err), rep.Notes, rep.Failed)
	}
	for _, f := range rep.Failed {
		if f.Count != 2 {
			t.Errorf("two targets fail, the old failures are not counted again: %+v", f)
		}
	}
	healed.Store(true)
	out, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	if err != nil {
		t.Fatalf("resume -retry-failed: %v\n%s", err, errOut)
	}
	rep = lastReport(t, errOut)
	if len(rep.Failed) != 0 || rep.Exit != exitOK {
		t.Errorf("after the retry nothing fails: exit %d, failed %+v", rep.Exit, rep.Failed)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "-retry-failed: 2 failed targets asked again, 0 still fail") {
		t.Errorf("no note says what the retry did: %v", rep.Notes)
	}
	if rep.Requests > 4 {
		t.Errorf("only the failed targets are asked again: %d requests", rep.Requests)
	}
	for _, p := range []string{"/boom", "/swagger-ui"} {
		if !strings.Contains(out, srv.URL+p) {
			t.Errorf("no row for %s:\n%s", p, out)
		}
	}
	// Nothing is retryable now.
	_, _, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	if err == nil || !strings.Contains(err.Error(), "nothing to retry") {
		t.Errorf("a second -retry-failed: %v", err)
	}
}
