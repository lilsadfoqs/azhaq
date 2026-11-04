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
