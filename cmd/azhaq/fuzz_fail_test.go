package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// A request that failed is reported with its cause and counted by class, and
// the failure is a row of the workspace: query -failed lists it.
func TestFuzzFailedRequestsNameTheirCauseAndLeaveAFailureRow(t *testing.T) {
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := refused.Addr().String()
	refused.Close() // nothing listens here now
	closing, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer closing.Close()
	go func() {
		for {
			c, err := closing.Accept()
			if err != nil {
				return
			}
			c.Close() // an answer that never comes: EOF
		}
	}()
	for _, tc := range []struct {
		name, addr, class string
		retryable         bool
	}{
		{"refused", addr, "connection refused", false},
		{"closed", closing.Addr().String(), "connection closed (EOF)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "f.db")
			args := []string{"-u", "http://" + tc.addr + "/FUZZ", "-w", numberedWords(t, 3), "-ac=false", "-mc", "all", "-t", "1", "-db", db}
			_, rep, err := fuzzRows(t, args...)
			if exitCode(err) != exitPartial {
				t.Fatalf("exit %d, want %d", exitCode(err), exitPartial)
			}
			if len(rep.Failed) != 1 {
				t.Fatalf("failed %+v", rep.Failed)
			}
			f := rep.Failed[0]
			if f.Error != tc.class || f.Retryable != tc.retryable || f.Count < 1 || len(f.Targets) != 1 || f.Targets[0] != "127.0.0.1" {
				t.Errorf("failed %+v, want %q retryable %v", f, tc.class, tc.retryable)
			}
			want := "failed with " + tc.class + "; the first: "
			notes := strings.Join(rep.Notes, "\n")
			if !strings.Contains(notes, want) || strings.Contains(notes, "/FUZZ") || strings.Contains(notes, "/1") {
				t.Errorf("notes %q, want %q and no URL", rep.Notes, want)
			}
			out, _, err := captureBoth(t, func() error { return run([]string{"query", "-db", db, "-failed"}) })
			if err != nil {
				t.Fatal(err)
			}
			line := "http://" + tc.addr + "/\tazhaq-fuzz\t" + tc.class
			if tc.retryable {
				line += "\tretryable"
			}
			if !strings.Contains(out, line) {
				t.Errorf("query -failed: %q, want %q", out, line)
			}
			if err := run([]string{"resume", "-db", db, "-retry-failed"}); err == nil || !strings.Contains(err.Error(), "does not apply to a fuzz run") {
				t.Errorf("resume -retry-failed: %v", err)
			}
		})
	}
}
