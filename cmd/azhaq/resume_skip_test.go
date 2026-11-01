package main

import (
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
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

// A range scan the budget stopped and a resume ask each address once between
// them: no connection of the ledger repeats another.
func TestResumeRangeScanAsksEachAddressOnce(t *testing.T) {
	t.Chdir(t.TempDir())
	args := []string{"-cidr", "127.0.0.0/28", "-allow", "127.0.0.0/28", "-ports", "9", "-sources", "none", "-ledger", "l.jsonl", "-db", "r.db"}
	_, rep, code := runContract(t, append([]string{"run", "-max-requests", "5"}, args...)...)
	if code != exitLimit {
		t.Fatalf("the first run: exit %d, stopped %q, failed %+v", code, rep.Stopped, rep.Failed)
	}
	_, rep, code = runContract(t, "resume", "-db", "r.db", "-max-requests", "0")
	if code != exitOK {
		t.Fatalf("resume: exit %d, stopped %q, failed %+v", code, rep.Stopped, rep.Failed)
	}
	seen := map[string]int{}
	if err := ledger.Read("l.jsonl", func(e ledger.Entry) error {
		if e.Kind == "tcp" && e.IsTarget() {
			seen[e.Target]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 16 {
		t.Errorf("%d addresses were asked, want 16: %v", len(seen), seen)
	}
	for target, n := range seen {
		if n > 1 {
			t.Errorf("%s was asked %d times", target, n)
		}
	}
}

// Names that point to one address are one endpoint in the summary and in
// query, with the names on its row.
func TestRunCountsAPortOnceWhateverNamesPointToTheAddress(t *testing.T) {
	port := portsServer(t)
	zone := serveZone(t, fakeZone{a: map[string]string{"a.example.test": "127.0.0.1", "b.example.test": "127.0.0.1"}})
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "run", "-list", hostsFile(t, "a.example.test", "b.example.test"), "-ports", port,
		"-resolvers", zone, "-allow", "example.test", "-allow", "127.0.0.1", "-sources", "none", "-skip", "http,tls,paths", "-db", "n.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	var rows []map[string]any
	for _, r := range jsonRows(t, out) {
		if r["type"] == "Port" {
			rows = append(rows, r)
		}
	}
	if len(rows) != 1 || rows[0]["key"] != "127.0.0.1:"+port+"/tcp" {
		t.Fatalf("port rows %v", rows)
	}
	if names := fmt.Sprint(rows[0]["names"]); names != "[a.example.test b.example.test]" {
		t.Errorf("names %s", names)
	}
	if rep.Counts["ports"] != 1 {
		t.Errorf("the summary counts %d ports: %v", rep.Counts["ports"], rep.Counts)
	}
	q, _, _ := runContract(t, "query", "-db", "n.db", "-type", "Port", "-fields", "key,names")
	if n := len(lines(q)); n != 1 {
		t.Errorf("query lists %d port rows:\n%s", n, q)
	}
}

// A capped ports resume names its leftovers in ports to connect, and counts
// the one address it was asked about.
func TestCappedPortsResumeNoteNamesPorts(t *testing.T) {
	open, _ := countedListener(t)
	t.Chdir(t.TempDir())
	ports := "1,2,3,4,5,6," + open
	if _, _, code := runContract(t, "ports", "-host", "127.0.0.1", "-p", ports, "-detect", "none", "-order", "asc", "-max-requests", "3", "-db", "p.db"); code != exitLimit {
		t.Fatalf("the first run: exit %d", code)
	}
	_, rep, code := runContract(t, "resume", "-db", "p.db", "-max-requests", "3")
	if code != exitLimit {
		t.Fatalf("resume: exit %d, stopped %q", code, rep.Stopped)
	}
	if rep.Counts["addresses"] != 1 {
		t.Errorf("the resume counts %d addresses, want 1: %v", rep.Counts["addresses"], rep.Counts)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "no task finished: each one left needs more than 3 connections (one per port to connect") || strings.Contains(notes, "path sweep") {
		t.Errorf("the note does not speak of ports: %q", rep.Notes)
	}
}

func TestNoTaskFinishedNoteSpeaksTheCommandsTerms(t *testing.T) {
	for cmd, want := range map[string]string{"ports": "3 connections", "dirs": "a path sweep needs one per word", "crawl": "3 requests; raise"} {
		if got := noTaskFinished(cmd, 3); !strings.Contains(got, want) {
			t.Errorf("%s: %q lacks %q", cmd, got, want)
		}
	}
	if got := noTaskFinished("crawl", 3); strings.Contains(got, "path sweep") {
		t.Errorf("crawl: %q", got)
	}
}
