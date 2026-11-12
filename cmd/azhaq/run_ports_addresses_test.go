package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run -ports over a range: the summary says how many addresses the scan asked
// and how many it found a port open on, apart from counts.addresses (the rows
// the map holds), and the first is the ledger's: every address connected to.
func TestRunPortsNamesAddressesScannedAndOpen(t *testing.T) {
	// A web server, so the map that follows the open port gets an answer:
	// a listener that hangs up at once makes the web probe fail now and then.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	l := srv.Listener
	_, port, _ := net.SplitHostPort(l.Addr().String())
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-cidr", "127.0.0.0/29", "-ports", port, "-port-detect", "none", "-allow", "127.0.0.0/29", "-sources", "none", "-db", "r.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	if rep.AddressesScanned == nil || *rep.AddressesScanned != 8 {
		t.Errorf("addresses_scanned %v, want 8 (the /29)", rep.AddressesScanned)
	}
	if rep.AddressesOpen == nil || *rep.AddressesOpen != 1 {
		t.Errorf("addresses_open %v, want 1 (only 127.0.0.1 listens)", rep.AddressesOpen)
	}
	if rep.Counts["addresses"] == 8 {
		t.Errorf("counts.addresses is %d: it is the rows, not the scan", rep.Counts["addresses"])
	}
	// The ledger holds the same addresses: a connect to the port of each.
	raw, err := os.ReadFile(filepath.Join(".", "r.db.ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		var e struct{ Kind, Target, Host, Collector string }
		if json.Unmarshal([]byte(line), &e) == nil && e.Kind == "tcp" && e.Collector == "azhaq-ports" && strings.HasSuffix(e.Target, ":"+port) {
			hosts[e.Host] = true
		}
	}
	if len(hosts) != 8 {
		t.Errorf("the ledger holds connects to %d addresses of the scan, the summary says 8: %v", len(hosts), hosts)
	}
	// The next pass is counted from the same number, not from the connects.
	if next := strings.Join(rep.Next, "\n"); !strings.Contains(next, "not asked on 8 addresses") {
		t.Errorf("the next pass does not count 8 addresses: %s", next)
	}
}

// An address that is in the range and also given on its own is one address.
// Every total of the summary is the ledger's: lines to targets are requests,
// the probes written on a connection are their own total beside it, and the
// addresses are the distinct ones the ledger connected to.
func TestRunPortsTotalsReconcileWithLedger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	t.Chdir(t.TempDir())
	if err := os.WriteFile("l.txt", []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rep, code := runContract(t, "run", "-list", "l.txt", "-cidr", "127.0.0.0/29", "-ports", port, "-allow", "127.0.0.0/29", "-sources", "none", "-db", "r.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	raw, err := os.ReadFile("r.db.ledger.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int64{}
	hosts := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		var e struct{ Kind, Class, Host, Collector string }
		if json.Unmarshal([]byte(line), &e) != nil || e.Kind == "seal" || e.Kind == "" {
			continue
		}
		switch {
		case e.Class == "dns":
			by["dns"]++
		case e.Kind == "probe":
			by["probe"]++
		case e.Class == "target":
			by["target"]++
			if e.Kind == "tcp" {
				by["tcp"]++
			}
			if e.Kind == "tcp" && e.Collector == "azhaq-ports" {
				hosts[e.Host] = true
			}
		}
	}
	if by["probe"] == 0 {
		t.Fatalf("the scan wrote no probe: the test does not reach the case (%v)", by)
	}
	if rep.Requests != by["target"] || rep.Probes != by["probe"] || rep.Connections != by["tcp"] || rep.DNSQueries != by["dns"] {
		t.Errorf("summary requests %d connections %d probes %d dns %d, ledger %v", rep.Requests, rep.Connections, rep.Probes, rep.DNSQueries, by)
	}
	if rep.AddressesScanned == nil || *rep.AddressesScanned != len(hosts) || len(hosts) != 8 {
		t.Errorf("addresses_scanned %v, the ledger connected to %d distinct addresses (want 8): %v", deref(rep.AddressesScanned), len(hosts), hosts)
	}
	if rep.AddressesOpen == nil || *rep.AddressesOpen != 1 {
		t.Errorf("addresses_open %v, want 1", deref(rep.AddressesOpen))
	}
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// A range a limit stopped is stored once for each run that touched it, and
// each row counts what the block had finished so far: the summary counts the
// block's addresses once, never above the range, however often it resumes.
func TestRunPortsAddressesScannedDoNotGrowOnResume(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	t.Chdir(t.TempDir())
	args := []string{"-allow", "127.0.0.0/29", "-sources", "none", "-skip", "subs", "-rate", "0", "-db", "r.db", "-max-requests", "12"}
	_, rep, _ := runContract(t, append([]string{"run", "-cidr", "127.0.0.0/29", "-ports", port + ",1"}, args...)...)
	for i := 0; i < 30 && rep.Exit == exitLimit; i++ {
		if rep.AddressesScanned != nil && *rep.AddressesScanned > 8 {
			t.Fatalf("resume %d: addresses_scanned %d for a range of 8", i, *rep.AddressesScanned)
		}
		_, rep, _ = runContract(t, "resume", "-db", "r.db", "-max-requests", "12", "-rate", "0")
	}
	if rep.Exit != exitOK {
		t.Fatalf("the scan did not finish: exit %d: %q", rep.Exit, rep.Stopped)
	}
	if rep.AddressesScanned == nil || *rep.AddressesScanned != 8 {
		t.Errorf("addresses_scanned %v after the resumes, want 8", rep.AddressesScanned)
	}
	if rep.AddressesOpen == nil || *rep.AddressesOpen != 1 {
		t.Errorf("addresses_open %v after the resumes, want 1", rep.AddressesOpen)
	}
}

// A port scan a limit stopped says, on the first line of the text summary and
// in the top-level not_asked of the JSON, how many ports of how many addresses
// it never asked and the resume command that asks them. The ports are the
// ledger's: the connects sent and the ports not asked make up the scan.
func TestRunPortsStoppedByALimitSaysWhatWasNotAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	args := []string{"-cidr", "127.0.0.0/29", "-ports", "1,2,3", "-allow", "127.0.0.0/29", "-sources", "none", "-skip", "subs", "-rate", "0", "-max-requests", "10"}
	_, rep, code := runContract(t, append([]string{"run", "-db", "n.db"}, args...)...)
	if code != exitLimit {
		t.Fatalf("exit %d: %q", code, rep.Stopped)
	}
	if rep.NotAsked == nil {
		t.Fatalf("no not_asked in the summary: %q", rep.Stopped)
	}
	raw, err := os.ReadFile("n.db.ledger.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	connects := 0
	for _, line := range strings.Split(string(raw), "\n") {
		var e struct{ Kind, Collector string }
		if json.Unmarshal([]byte(line), &e) == nil && e.Kind == "tcp" && e.Collector == "azhaq-ports" {
			connects++
		}
	}
	if rep.NotAsked.Ports != 8*3-connects || rep.NotAsked.Addresses < 1 || rep.NotAsked.Addresses > 8 {
		t.Errorf("not_asked %+v with %d connects in the ledger: want %d ports of 1 to 8 addresses", *rep.NotAsked, connects, 8*3-connects)
	}
	if rep.NotAsked.Resume != rep.Resume || !strings.HasPrefix(rep.Resume, "azhaq resume -db n.db") {
		t.Errorf("resume %q, not_asked.resume %q", rep.Resume, rep.NotAsked.Resume)
	}
	_, errOut, _ := cli(t, append([]string{"run", "-db", "t.db"}, args...)...)
	first := strings.SplitN(errOut, "\n", 2)[0]
	for _, line := range lines(errOut) {
		if strings.HasPrefix(line, "azhaq run:") {
			first = line
		}
	}
	if !strings.Contains(first, " ports of ") || !strings.Contains(first, "not asked; azhaq resume -db t.db") {
		t.Errorf("the first line of the summary does not say what was not asked: %s", first)
	}
}
