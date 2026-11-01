package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// An ingested naabu scan gives the same Port rows as azhaq's own: one for each
// host, port and protocol, the lines it repeats folded, in query and in the
// summary.
func TestIngestNaabuMakesPortRows(t *testing.T) {
	in := filepath.Join(t.TempDir(), "naabu.json")
	lines := []string{
		`{"ip":"127.0.0.1","port":22,"protocol":"tcp","tls":false}`,
		`{"ip":"127.0.0.1","port":8080,"protocol":"tcp","tls":false}`,
		`{"ip":"127.0.0.1","port":22,"protocol":"tcp","tls":false}`,
		`{"ip":"127.0.0.1","port":53,"protocol":"udp","tls":false}`,
	}
	if err := os.WriteFile(in, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "n.db")
	if _, _, err := captureBoth(t, func() error { return cmdIngest([]string{in, "-db", db}) }); err != nil {
		t.Fatal(err)
	}
	out, rep, code := runContract(t, "query", "-db", db, "-type", "Port")
	if code != exitOK {
		t.Fatalf("query exit %d", code)
	}
	var keys []string
	for _, r := range jsonRows(t, out) {
		keys = append(keys, r["key"].(string)+" "+r["state"].(string))
	}
	sort.Strings(keys)
	want := "127.0.0.1:22/tcp open,127.0.0.1:53/udp open,127.0.0.1:8080/tcp open"
	if got := strings.Join(keys, ","); got != want {
		t.Errorf("port rows %q, want %q", got, want)
	}
	if rep.Counts["open ports"] != 3 {
		t.Errorf("summary counts %v", rep.Counts)
	}
}
