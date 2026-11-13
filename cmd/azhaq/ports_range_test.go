package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// pgStub answers a startup message the way PostgreSQL 16 does a protocol it
// does not speak: with the protocol versions it supports, and no release.
func pgStub(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				if n, _ := c.Read(buf); n > 0 {
					c.Write([]byte("EFATAL:  unsupported frontend protocol 1.0: server supports 3.0 to 3.0\n\x00"))
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// A PostgreSQL that states no version has an empty version: the range its
// protocols allow is version_range, with the answer it came from, and no
// advisory is matched on it, from the index azhaq carries or a record of
// the user's that names PostgreSQL.
func TestPortsPostgresRangeIsNotAVersionAndMatchesNoAdvisory(t *testing.T) {
	useBuiltinIndex(t)
	egress.Reset()
	t.Cleanup(egress.Reset)
	port := pgStub(t)
	mine := `[{"id":"CVE-TEST-0200","affected":[{"package":{"name":"PostgreSQL"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"99"}]}]}]}]`
	out, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", strconv.Itoa(port), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-detect", "all",
			"-advisory-source", writeAdvFixture(t, mine)})
	})
	if err != nil {
		t.Fatalf("ports: %v\n%s", err, errOut)
	}
	var row map[string]any
	for _, line := range strings.Split(out, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["port"] != nil {
			row = m
		}
	}
	if row == nil || row["product"] != "PostgreSQL" {
		t.Fatalf("no PostgreSQL row in:\n%s", out)
	}
	if v, has := row["version"]; has {
		t.Errorf("version %q, want none: the server states no version", v)
	}
	if row["version_range"] != "14 - 17" || !strings.Contains(row["version_range_basis"].(string), "protocol 3.0 to 3.0") {
		t.Errorf("version_range %v, basis %v", row["version_range"], row["version_range_basis"])
	}
	rep := lastReport(t, errOut)
	if len(rep.Advisories) != 0 || rep.Counts["advisory leads"] != 0 {
		t.Errorf("%d advisory leads from a version range: %+v", len(rep.Advisories), rep.Advisories)
	}
}
