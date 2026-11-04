package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
)

// reportEvidence is a roles run holding n cross-read findings.
func reportEvidence(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	ev, err := store.OpenEvidence(filepath.Join(dir, evidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	var rows []store.EvidenceRow
	for i := 0; i < n; i++ {
		u := "https://s.test/api/items/" + string(rune('1'+i))
		row := roleRow{URL: u, From: "https://s.test/api/items/{id}" + strings.Repeat("x", i), Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, Confidence: confProved, Answers: map[string]answer{}}
		rows = append(rows, evRow(t, row, ans("bob", "answer", u, 200, `{"a":1}`, "curl -sS '"+u+"'")))
	}
	if err := ev.Save([]string{"alice", "bob"}, rows); err != nil {
		t.Fatal(err)
	}
	ev.Close()
	return dir
}

// -o is a directory when it exists, ends in a slash or several reports go
// to it; one report to another path is a file.
func TestReportOutputIsADirectoryOrAFile(t *testing.T) {
	dir := reportEvidence(t, 3)
	count := func(p string) int { f, _ := filepath.Glob(filepath.Join(p, "*.md")); return len(f) }

	// Several reports, no slash, no such path: a directory of three files.
	out := filepath.Join(t.TempDir(), "reports-out")
	if err := cmdReport([]string{"-dir", dir, "-o", out}); err != nil {
		t.Fatal(err)
	}
	if !isDir(out) || count(out) != 3 {
		t.Fatalf("%s holds %d reports (dir %v), want 3 files", out, count(out), isDir(out))
	}
	// With the slash: the same.
	out2 := filepath.Join(t.TempDir(), "with-slash") + "/"
	if err := cmdReport([]string{"-dir", dir, "-o", out2}); err != nil {
		t.Fatal(err)
	}
	if count(out2) != 3 {
		t.Fatalf("slash: %d reports", count(out2))
	}
	// An existing file cannot take several reports.
	f := filepath.Join(t.TempDir(), "x.md")
	if err := os.WriteFile(f, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdReport([]string{"-dir", dir, "-o", f}); err == nil {
		t.Error("several reports were written over a file")
	}
	if b, _ := os.ReadFile(f); string(b) != "keep" {
		t.Errorf("the file was overwritten: %q", b)
	}

	// One report to a non-directory path: a file.
	one := reportEvidence(t, 1)
	file := filepath.Join(t.TempDir(), "one.md")
	if err := cmdReport([]string{"-dir", one, "-o", file}); err != nil {
		t.Fatal(err)
	}
	if isDir(file) {
		t.Fatal("one report made a directory")
	}
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), "bob") {
		t.Errorf("file:\n%s", b)
	}
	// One report to an existing directory: a file inside it.
	d := t.TempDir()
	if err := cmdReport([]string{"-dir", one, "-o", d}); err != nil {
		t.Fatal(err)
	}
	if count(d) != 1 {
		t.Errorf("existing dir holds %d reports", count(d))
	}
}
