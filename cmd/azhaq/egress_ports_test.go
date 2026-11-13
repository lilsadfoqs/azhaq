package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A run that asks a target over HTTP and also connects to its ports: the
// summary's requests are the ledger's lines to targets, requests and
// connections both, and the note names what the ledger holds by class.
func TestRunPortsSummaryReconcilesWithLedger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>home</title><a href="/a">a</a> <a href="/go">go</a></html>`)
		case "/go":
			http.Redirect(w, r, "/a", http.StatusFound)
		case "/a":
			fmt.Fprint(w, `<html><title>a</title></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	shut, _ := net.Listen("tcp", "127.0.0.1:0") // a port nothing listens on, once closed
	shutPort := fmt.Sprint(shut.Addr().(*net.TCPAddr).Port)
	shut.Close()
	dir := t.TempDir()
	led := filepath.Join(dir, "run.ledger.jsonl")
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-cidr", "127.0.0.1/32", "-ports", u.Port()+","+shutPort, "-port-detect", "none",
		"-ledger", led, "-db", filepath.Join(dir, "run.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	targets, conns := 0, 0
	_ = ledger.Read(led, func(e ledger.Entry) error {
		if e.IsTarget() && e.Kind != ledger.KindSeal {
			targets++
			if e.Kind == "tcp" {
				conns++
			}
		}
		return nil
	})
	if conns == 0 {
		t.Fatalf("no port connect in the ledger")
	}
	if int64(targets) != rep.Requests {
		t.Errorf("the summary says %d requests, the ledger lists %d lines to targets", rep.Requests, targets)
	}
	want := fmt.Sprintf("ledger: %d recorded in ", targets)
	var found bool
	for _, n := range rep.Notes {
		found = found || strings.HasPrefix(n, want)
		if strings.Contains(n, "the summary counts") {
			t.Errorf("a note says the counts differ: %s", n)
		}
	}
	detail := fmt.Sprintf(": %d to targets (%d requests, %d connections), sealed ", targets, targets-conns, conns)
	if !found || !strings.Contains(strings.Join(rep.Notes, "\n"), detail) {
		t.Errorf("no note starts %q and holds %q: %q", want, detail, rep.Notes)
	}
}

// The note names each class the ledger holds, so a DNS query or a source's
// request is not taken for a request to a target.
func TestLedgerNoteNamesTheClasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.ledger.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	add := func(n int, e ledger.Entry) {
		for range n {
			l.Record(e)
		}
	}
	add(210, ledger.Entry{Kind: "http", Class: ledger.ClassTarget, Method: "GET", Target: "http://127.0.0.1/"})
	add(4, ledger.Entry{Kind: "tcp", Class: ledger.ClassTarget, Target: "127.0.0.1:80"})
	add(1, ledger.Entry{Kind: "dns", Class: ledger.ClassDNS, Method: "A", Target: "1.1.1.1:53", Host: "a.example.org"})
	add(2, ledger.Entry{Kind: "http", Class: ledger.ClassSource, Method: "GET", Target: "https://crt.sh/"})
	r := &runLedger{l: l, owned: true, stopKill: func() {}}
	rep := &report{Requests: 213}
	r.close(rep)
	got := strings.Join(rep.Notes, "\n")
	for _, want := range []string{
		"ledger: 217 recorded in ",
		": 214 to targets (210 requests, 4 connections), 2 to third-party sources, 1 DNS query, sealed ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no note says %q:\n%s", want, got)
		}
	}
	// A summary that counts 213 where the ledger lists 214 is not a note to read past: it is an
	// internal error, exit 1, naming both numbers.
	rep.settle()
	if rep.Exit != exitError || rep.Complete || !strings.Contains(rep.Error, "the summary says 213, the rows say 214") {
		t.Errorf("exit %d, complete %v, error %q: a summary that disagrees with the ledger is an internal error", rep.Exit, rep.Complete, rep.Error)
	}
	// A second run in the same file counts its own lines, and says the file holds more.
	l2, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Record(ledger.Entry{Kind: "http", Class: ledger.ClassTarget, Method: "GET", Target: "http://127.0.0.1/"})
	r2 := &runLedger{l: l2, owned: true, stopKill: func() {}, from: l2.Count() - 1}
	rep2 := &report{Requests: 1}
	r2.close(rep2)
	got = strings.Join(rep2.Notes, "\n")
	if !strings.Contains(got, "ledger: 1 recorded in ") || !strings.Contains(got, ": 1 to targets (1 request, 0 connections), sealed ") || !strings.Contains(got, " holds 220 lines in all, the lines of the runs before this one included") {
		t.Errorf("the second run's note: %s", got)
	}
	if rep2.settle(); len(rep2.problems) > 0 {
		t.Errorf("the counts agree: %v", rep2.problems)
	}
}

// The note at the end of a run comes from what the ledger counted as it
// wrote: the file is not read again (a full-range scan spent the better part
// of a second reading its 65,535 lines twice). With the file gone the count
// is still right.
func TestLedgerNoteDoesNotReadTheFileAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.ledger.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		l.Record(ledger.Entry{Kind: "tcp", Class: ledger.ClassTarget, Target: "127.0.0.1:80", Collector: "azhaq-ports"})
	}
	l.Record(ledger.Entry{Kind: "http", Class: ledger.ClassTarget, Method: "GET", Target: "http://127.0.0.1/", Collector: "azhaq-urls"})
	if err := os.Remove(path); err != nil {
		t.Skip("the file cannot be removed while open:", err)
	}
	r := &runLedger{l: l, owned: true, stopKill: func() {}}
	rep := &report{Requests: 31}
	r.close(rep)
	got := strings.Join(rep.Notes, "\n")
	if !strings.Contains(got, "ledger: 31 recorded in ") || !strings.Contains(got, ": 31 to targets (1 request, 30 connections), sealed ") {
		t.Errorf("the note without the file: %s", got)
	}
	if strings.Contains(got, "not counted") || strings.Contains(got, "the summary counts") {
		t.Errorf("the note read the file or disagreed: %s", got)
	}
}

func TestScanProcsFollowsTheRate(t *testing.T) {
	for _, c := range []struct {
		rate float64
		ncpu int
		want int
	}{{1, 20, 1}, {100, 20, 1}, {15000, 20, 1}, {50000, 20, 1}, {50001, 20, 2}, {150000, 20, 3}, {200000, 20, 4}, {1e6, 20, 4}, {1e6, 3, 3}, {10000, 1, 1}, {0, 20, 4}, {0, 2, 2}, {0, 1, 1}} {
		if got := scanProcs(c.rate, c.ncpu); got != c.want {
			t.Errorf("scanProcs(%v, %d) = %d, want %d", c.rate, c.ncpu, got, c.want)
		}
	}
}

// ports -rate sizes the scheduler to the rate: it runs on one core when one
// carries it (more cores only wake each other for every connect).
func TestPortsRateSizesTheScheduler(t *testing.T) {
	if runtime.NumCPU() < 2 || os.Getenv("GOMAXPROCS") != "" {
		t.Skip("one core, or GOMAXPROCS says how many")
	}
	was := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(was) })
	shut, _ := net.Listen("tcp", "127.0.0.1:0")
	port := fmt.Sprint(shut.Addr().(*net.TCPAddr).Port)
	shut.Close()
	cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-rate", "200", "-silent", "-ledger", "off")
	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Errorf("GOMAXPROCS %d after ports -rate 200, want 1", got)
	}
	cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-silent", "-ledger", "off")
	if got := runtime.GOMAXPROCS(0); got != min(4, runtime.NumCPU()) {
		t.Errorf("GOMAXPROCS %d after ports with no -rate, want 4", got)
	}
}
