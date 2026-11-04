package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dns neither reads nor writes the history subs keeps in azhaq-data/ (beside
// -db, or the current directory): a file planted there is not read, is not
// changed, and the run creates nothing next to it.
func TestDNSLeavesTheDefaultNameHistoryAlone(t *testing.T) {
	_, work := isolate(t)
	lab := startLab(t)
	hist := filepath.Join(work, "azhaq-data", "names", "lab.zz.json")
	if err := os.MkdirAll(filepath.Dir(hist), 0o755); err != nil {
		t.Fatal(err)
	}
	planted := `{"www.lab.zz": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}}`
	if err := os.WriteFile(hist, []byte(planted), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, db := range []string{"", filepath.Join(work, "ws", "w.db")} {
		args := []string{"-d", "nope.lab.zz", "-r", lab.addr, "-json"}
		if db != "" {
			if err := os.MkdirAll(filepath.Dir(db), 0o755); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-db", db)
		}
		rows, rep, code := dnsOut(t, args...)
		if code != exitOK || len(rows) != 0 || rep.Counts["asked"] != 1 {
			t.Errorf("-db %q: exit %d, rows %v, counts %v: dns asks the names it is given and no more", db, code, rows, rep.Counts)
		}
		if got, _ := os.ReadFile(hist); string(got) != planted {
			t.Errorf("-db %q: dns changed the history: %s", db, got)
		}
		if db != "" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(db), "azhaq-data")); err == nil {
				t.Errorf("dns made a history beside -db")
			}
		}
	}
	for _, f := range filesUnder(work) {
		rel, _ := filepath.Rel(work, f)
		if f != hist && !strings.HasPrefix(rel, filepath.Join("ws", "w.db")) {
			t.Errorf("dns wrote %s, which is neither its workspace nor the planted history", rel)
		}
	}
}
