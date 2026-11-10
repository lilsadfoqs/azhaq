package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// vhostServer is one web server for many names: it counts, by Host, the
// requests for /.git/HEAD, one of the built-in path checks.
func vhostServer(t *testing.T) (port string, probes func(host string) int) {
	t.Helper()
	var mu sync.Mutex
	got := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			if r.URL.Path == "/.git/HEAD" {
				mu.Lock()
				got[strings.Split(r.Host, ":")[0]]++
				mu.Unlock()
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>shop</title>")
	}))
	t.Cleanup(srv.Close)
	_, port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return port, func(host string) int {
		mu.Lock()
		defer mu.Unlock()
		return got[host]
	}
}

// Hostnames from a list that share one address are one web server with
// several virtual hosts: each answering name gets its own path sweep.
func TestRunListOfNamesOnOneAddressSweepsEachName(t *testing.T) {
	port, probes := vhostServer(t)
	names := []string{"shop.zz", "www.shop.zz", "web.shop.zz"}
	zone := serveZone(t, fakeZone{
		a:     map[string]string{"shop.zz": "127.0.0.1", "www.shop.zz": "127.0.0.1"},
		cname: map[string]string{"web.shop.zz": "www.shop.zz"},
	})
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-list", hostsFile(t, names...), "-allow", "shop.zz", "-allow", "127.0.0.0/24",
		"-sources", "none", "-resolvers", zone, "-web-ports", port, "-no-history", "-db", "s.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	for _, n := range names {
		if probes(n) == 0 {
			t.Errorf("no path check was sent with Host %s", n)
		}
	}
	if len(rep.PathChecks) != len(names) {
		t.Fatalf("path_checks: %+v", rep.PathChecks)
	}
	for _, c := range rep.PathChecks {
		if c.Sent == nil || *c.Sent == 0 {
			t.Errorf("%s: no sweep on record: %+v", c.Service, c)
		}
	}
}

// A path sweep the run listed that left no record, with no stop to explain
// it, makes the run incomplete: exit 3, the service named in failed.
func TestUnrecordedPathSweepWithNoStopIsIncomplete(t *testing.T) {
	rep := &report{Command: "run", PathChecks: []pathCheck{{Service: "http://lab.zz", Listed: 51, Reason: "its sweep left no record"}}}
	rep.settle()
	if rep.Exit != exitPartial || rep.Complete {
		t.Fatalf("exit %d, complete %v: want exit %d and incomplete", rep.Exit, rep.Complete, exitPartial)
	}
	if len(rep.Failed) != 1 || rep.Failed[0].Targets[0] != "http://lab.zz" || !strings.Contains(rep.Failed[0].Error, "left no record") {
		t.Errorf("failed: %+v", rep.Failed)
	}
	if rep.Failures != 1 {
		t.Errorf("failures %d, want 1", rep.Failures)
	}
}

// A run that was stopped has the sweep left to resume: it is exit 4 with no
// failure added, and a sweep that did record is no failure at all.
func TestUnrecordedPathSweepOfAStoppedRunIsNotAFailure(t *testing.T) {
	sent := 51
	rep := &report{Command: "run", Stopped: "the request budget of 10 is spent", PathChecks: []pathCheck{{Service: "http://lab.zz", Listed: 51}}}
	rep.settle()
	if rep.Exit != exitLimit || len(rep.Failed) != 0 {
		t.Errorf("stopped run: exit %d, failed %+v", rep.Exit, rep.Failed)
	}
	done := &report{Command: "run", PathChecks: []pathCheck{{Service: "http://lab.zz", Listed: 51, Sent: &sent}}}
	done.settle()
	if done.Exit != exitOK || !done.Complete || len(done.Failed) != 0 {
		t.Errorf("recorded sweep: exit %d, failed %+v", done.Exit, done.Failed)
	}
}

// A sweep whose service has a URL among the work the run left (past
// -depth, over a cap) is for azhaq resume, not one that did not run: the
// row says so and the run is not failed for it.
func TestPathSweepLeftForResumeIsNotFailed(t *testing.T) {
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: []byte(`{"url":"http://lab.zz/"}`)}}}
	left := leftOrigins([]types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://lab.zz/"}}})
	cs := pathChecks(obs, []string{"/.git/HEAD"}, nil, left)
	if len(cs) != 1 || cs[0].Sent != nil || !strings.Contains(cs[0].Reason, "azhaq resume sweeps it") {
		t.Fatalf("path_checks: %+v", cs)
	}
	rep := &report{Command: "run", PathChecks: cs}
	rep.settle()
	if rep.Exit != exitOK || len(rep.Failed) != 0 {
		t.Errorf("exit %d, failed %+v: a sweep left for resume is no failure", rep.Exit, rep.Failed)
	}
	if cs := pathChecks(obs, []string{"/.git/HEAD"}, nil, nil); len(cs) != 1 || !strings.Contains(cs[0].Reason, "left no record") {
		t.Errorf("with nothing left: %+v", cs)
	}
}
