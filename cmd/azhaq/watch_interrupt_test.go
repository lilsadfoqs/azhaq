package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// watchUntilSignal runs watch in-process and ends the test if it does not
// stop in a minute.
func watchUntilSignal(t *testing.T, args []string) (stderr string, err error) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, stderr, err = captureAll(t, func() error { return cmdWatch(args) })
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		<-done
		t.Fatal("watch did not stop")
	}
	return stderr, err
}

// A watch a signal cuts during a cycle's run ends stopped (exit 4, not
// complete), names the interruption and the cycle, and sends nothing: the
// partial run is not compared, and no delivery is counted as failed (#362).
func TestWatchInterruptedDuringARunExitsStopped(t *testing.T) {
	var once sync.Once
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a></html>`)
			return
		}
		once.Do(func() { _ = syscall.Kill(syscall.Getpid(), syscall.SIGINT) })
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer site.Close()
	hook := 0
	var mu sync.Mutex
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); hook++; mu.Unlock() }))
	defer recv.Close()
	db := filepath.Join(t.TempDir(), "ws.db")
	for _, every := range [][]string{nil, {"-every", "1h"}} {
		args := append(append([]string{"-db", db, "-always", "-notify", recv.URL + "/hook", "-notify-rate", "0", "-json"}, every...),
			"--", "-url", site.URL+"/", "-allow", "127.0.0.1", "-no-paths")
		errOut, err := watchUntilSignal(t, args)
		rep := lastReport(t, errOut)
		if exitCode(err) != exitLimit || rep.Exit != exitLimit || rep.Complete || !strings.Contains(rep.Stopped, "interrupted") || !strings.Contains(rep.Stopped, "cycle 1") {
			t.Errorf("%v: exit %d (summary %d), complete %v, stopped %q\n%s", every, exitCode(err), rep.Exit, rep.Complete, rep.Stopped, errOut)
		}
		if rep.Counts["deliveries failed"] != 0 || strings.Contains(errOut, "context canceled") {
			t.Errorf("%v: a cut run is not a failed delivery:\n%s", every, errOut)
		}
		once = sync.Once{}
	}
	mu.Lock()
	defer mu.Unlock()
	if hook != 0 {
		t.Errorf("%d notifications of a partial run", hook)
	}
}

// A signal that cuts a notification ends watch stopped too: the delivery is
// not sent, not failed.
func TestWatchInterruptedDuringANotificationExitsStopped(t *testing.T) {
	site, _ := changingSite(t)
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer recv.Close()
	for _, every := range [][]string{nil, {"-every", "1h"}} {
		db := filepath.Join(t.TempDir(), "ws.db")
		args := append(append([]string{"-db", db, "-always", "-notify", recv.URL + "/hook", "-notify-rate", "0", "-json"}, every...),
			"--", "-url", site.URL+"/", "-allow", "127.0.0.1", "-no-paths")
		errOut, err := watchUntilSignal(t, args)
		rep := lastReport(t, errOut)
		if exitCode(err) != exitLimit || rep.Exit != exitLimit || rep.Complete || !strings.Contains(rep.Stopped, "cycle 1") {
			t.Errorf("%v: exit %d (summary %d), complete %v, stopped %q\n%s", every, exitCode(err), rep.Exit, rep.Complete, rep.Stopped, errOut)
		}
		if rep.Counts["deliveries failed"] != 0 || strings.Contains(errOut, "context canceled") || !strings.Contains(strings.Join(rep.Notes, "\n"), "not sent because the watch was interrupted") {
			t.Errorf("%v: the cut delivery is counted as failed, or not said to be unsent:\n%s", every, errOut)
		}
	}
}
