package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// reasonFor says whether the report lists a URL of the port as skipped with reason.
func reasonFor(rep report, port, reason string) bool {
	for _, s := range rep.Skipped {
		if strings.Contains(s.Target, ":"+port) && s.Reason == reason {
			return true
		}
	}
	return false
}

// With no -allow and no -scope, a URL target holds its host to its port: the
// page's link and its script's fetch() URL to another service of the host are
// listed as not requested, and nothing is sent there.
func TestRunTargetPortHoldsTheHost(t *testing.T) {
	for name, extra := range map[string][]string{
		"default":     nil,
		"crawl scope": {"-crawl-scope", "fqdn", "-depth", "4"},
	} {
		t.Run(name, func(t *testing.T) {
			a, b, bHits := twoPorts(t)
			dir := t.TempDir()
			led := filepath.Join(dir, "run.ledger.jsonl")
			args := append([]string{"run", "-url", a.URL + "/", "-sources", "none", "-no-paths", "-ledger", led, "-db", filepath.Join(dir, "run.db"), "-json"}, extra...)
			_, errOut, code := cli(t, args...)
			rep := lastReport(t, errOut)
			if code != exitOK && code != exitPartial {
				t.Fatalf("exit %d: %+v", code, rep)
			}
			if bHits.Load() != 0 || ledgerMentions(t, led, srvPort(t, b)) != 0 {
				t.Fatalf("the other port got %d requests, the ledger names it %d times", bHits.Load(), ledgerMentions(t, led, srvPort(t, b)))
			}
			if rep.Requests == 0 {
				t.Fatalf("the target's own port was not asked: %+v", rep)
			}
			if !reasonFor(rep, srvPort(t, b), neterr.OutOfTargetPortReason) {
				t.Errorf("no URL of the other port is listed as skipped with the targets' reason: %+v", rep.Skipped)
			}
		})
	}
}

// The crawl command holds the same line, also under a crawl scope that would
// follow a link to another port of the host.
func TestCrawlTargetPortHoldsTheHost(t *testing.T) {
	a, b, bHits := twoPorts(t)
	led := filepath.Join(t.TempDir(), "crawl.ledger.jsonl")
	_, errOut, code := cli(t, "crawl", "-u", a.URL+"/", "-fs", "fqdn", "-ledger", led, "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if bHits.Load() != 0 || ledgerMentions(t, led, srvPort(t, b)) != 0 {
		t.Fatalf("the other port got %d requests, the ledger names it %d times", bHits.Load(), ledgerMentions(t, led, srvPort(t, b)))
	}
	if !reasonFor(rep, srvPort(t, b), neterr.OutOfTargetPortReason) {
		t.Errorf("no URL of the other port is listed as not requested with the targets' reason: %+v %q", rep.Skipped, rep.Notes)
	}
}

// -allow with the host alone (every port) lifts the hold: the other service is asked.
func TestRunAllowHostAsksEveryPort(t *testing.T) {
	a, _, bHits := twoPorts(t)
	dir := t.TempDir()
	_, errOut, code := cli(t, "run", "-url", a.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-crawl-scope", "fqdn",
		"-db", filepath.Join(dir, "run.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	if bHits.Load() == 0 {
		t.Errorf("-allow 127.0.0.1 holds no port, and the other service was not asked: %+v", rep.Skipped)
	}
	for _, s := range rep.Skipped {
		if s.Reason == neterr.OutOfTargetPortReason {
			t.Errorf("a URL is held to a port by targets that an -allow rule replaced: %+v", s)
		}
	}
}

// Another URL target on the other port allows that port too.
func TestRunTargetPortsOfSeveralURLs(t *testing.T) {
	a, b, bHits := twoPorts(t)
	dir := t.TempDir()
	_, errOut, code := cli(t, "run", "-url", a.URL+"/", "-url", b.URL+"/", "-sources", "none", "-no-paths", "-crawl-scope", "fqdn",
		"-db", filepath.Join(dir, "run.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	if bHits.Load() == 0 || reasonFor(rep, srvPort(t, b), neterr.OutOfTargetPortReason) {
		t.Errorf("a port a target names is held back: %d hits, %+v", bHits.Load(), rep.Skipped)
	}
}

// -ports asks every port of the host it is given, so the port of a URL target
// does not hold the scan; neither does it hold the ports command.
func TestPortsScanIgnoresTheURLTargetPort(t *testing.T) {
	t.Chdir(t.TempDir())
	first, dialedFirst := listenCount(t)
	second, dialedSecond := listenCount(t)
	dir := t.TempDir()
	_, errOut, code := cli(t, "run", "-url", "http://127.0.0.1:"+first+"/", "-ports", first+","+second, "-port-detect", "none", "-sources", "none",
		"-db", filepath.Join(dir, "p.db"), "-json")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	out, errOut, code := cli(t, "ports", "http://127.0.0.1:"+first+"/", "-p", second, "-detect", "none", "-json")
	if code != exitOK || !strings.Contains(out, `"port":`+second) {
		t.Fatalf("ports: exit %d\n%s\n%s", code, out, errOut)
	}
	time.Sleep(100 * time.Millisecond)
	if dialedFirst.Load() == 0 || dialedSecond.Load() < 2 {
		t.Errorf("connects: %d to the URL's port, %d to the other (run and ports)", dialedFirst.Load(), dialedSecond.Load())
	}
}
