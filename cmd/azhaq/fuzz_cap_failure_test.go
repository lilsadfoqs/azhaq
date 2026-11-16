package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// A request that failed is a failure row though the cap the retry would
// have run into came first: -max-requests 1 and 2 both name the refusal.
func TestFuzzMaxRequestsKeepsTheFailureOfTheRequestBeforeTheCap(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens here now
	// The cap stopped the run with work left: exit 4 (OUTPUT.md); with 2 it
	// was not reached, and nothing answered: exit 3.
	for _, c := range []struct {
		n    string
		exit int
	}{{"1", exitLimit}, {"2", exitPartial}} {
		n := c.n
		t.Run("max-requests "+n, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "c.db")
			_, rep, err := fuzzRows(t, "-u", "http://"+addr+"/?id=FUZZ", "-w", wlist(t, "one"), "-max-requests", n, "-allow", "127.0.0.1", "-db", db)
			if exitCode(err) != c.exit {
				t.Errorf("exit %d, want %d: %+v", exitCode(err), c.exit, rep)
			}
			if rep.Failures != 1 || len(rep.Failed) != 1 || rep.Failed[0].Error != "connection refused" {
				t.Errorf("failures %d, failed %+v, want one connection refused", rep.Failures, rep.Failed)
			}
			out, _, err := captureBoth(t, func() error { return run([]string{"query", "-db", db, "-failed"}) })
			if err != nil || !strings.Contains(out, "azhaq-fuzz\tconnection refused") {
				t.Errorf("query -failed: %q %v", out, err)
			}
		})
	}
}
