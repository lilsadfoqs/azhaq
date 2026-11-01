package main

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// countedListener is a TCP listener on 127.0.0.1 that counts the
// connections it accepts and closes them.
func countedListener(t *testing.T) (port string, accepted *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	accepted = new(atomic.Int64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, accepted
}

// -skip ports names the ports collector, and a resume told to skip it leaves
// the port tasks the stopped run kept alone: nothing is asked of the port, and
// the run ends complete, not with the tasks left.
func TestResumeSkipPortsLeavesTheQueuedPortTasks(t *testing.T) {
	port, accepted := countedListener(t)
	t.Chdir(t.TempDir())
	list := hostsFile(t, "127.0.0.1")
	_, rep, code := runContract(t, "run", "-list", list, "-ports", port, "-sources", "none", "-max-requests", "0", "-max-items", "1", "-db", "s.db")
	if code != exitLimit {
		t.Fatalf("the first run: exit %d, stopped %q", code, rep.Stopped)
	}
	before := accepted.Load()
	_, rep, code = runContract(t, "resume", "-db", "s.db", "-skip", "ports,subs", "-max-items", "100")
	if code != exitOK {
		t.Fatalf("resume -skip ports: exit %d, stopped %q, failed %+v", code, rep.Stopped, rep.Failed)
	}
	if n := accepted.Load() - before; n != 0 {
		t.Errorf("resume -skip ports connected to the port %d times", n)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "azhaq-ports: ") {
		t.Errorf("the summary does not say the port tasks were left out: %q", rep.Notes)
	}
}

func TestSkipNamesAreCollectors(t *testing.T) {
	for _, n := range []string{"ports", "azhaq-ports", "subs", "urls", "dns-brute", "paths"} {
		got, err := resolveSkip([]string{n})
		if err != nil || len(got) != 1 || !strings.HasPrefix(got[0], "azhaq-") {
			t.Errorf("-skip %s: %v %v", n, got, err)
		}
	}
	_, err := resolveSkip([]string{"port"})
	if err == nil || !strings.Contains(err.Error(), `"port"`) || !strings.Contains(err.Error(), "azhaq-ports") {
		t.Errorf("-skip port: %v", err)
	}
	t.Chdir(t.TempDir())
	_, _, code := runContract(t, "run", "-list", hostsFile(t, "127.0.0.1"), "-skip", "nosuch", "-db", "u.db")
	if code != exitUsage {
		t.Errorf("-skip nosuch: exit %d", code)
	}
}

func TestResumeSkipAddsToTheStoredSkip(t *testing.T) {
	stored := []string{"-url", "http://x/", "-skip", "azhaq-urls,azhaq-search", "-depth", "2"}
	runArgs, rest := mergeSkip(stored, []string{"-skip=ports", "-max-requests", "9"})
	if v, _ := flagValue(append(runArgs, rest...), "skip"); v != "azhaq-urls,azhaq-search,ports" {
		t.Errorf("-skip after the merge: %q (%v %v)", v, runArgs, rest)
	}
	if _, found := flagValue(runArgs, "skip"); found {
		t.Errorf("the stored -skip is still in %v", runArgs)
	}
	runArgs, rest = mergeSkip([]string{"-depth", "2"}, []string{"-skip", "ports"})
	if v, _ := flagValue(rest, "skip"); v != "ports" || len(runArgs) != 2 {
		t.Errorf("no stored -skip: %v %v", runArgs, rest)
	}
}
