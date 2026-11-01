package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRefRunReplayedWithItsFiles(t *testing.T) {
	work, azhaq, fresh = t.TempDir(), "/nonexistent/azhaq", false
	dir := t.TempDir()
	tool := filepath.Join(dir, "reftool")
	// Prints a line, writes -o's file, and counts its runs.
	script := "#!/bin/sh\necho run >> " + filepath.Join(dir, "count") + "\necho found\necho result > \"$2\"\n"
	if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")
	for i := range 2 {
		_ = os.Remove(out)
		got, m := run("t", 0x7fffffff, dir, tool, "-o", out)
		if string(got) != "found\n" || m.Cached != (i == 1) {
			t.Fatalf("run %d: %q cached=%v", i, got, m.Cached)
		}
		if b, err := os.ReadFile(out); err != nil || string(b) != "result\n" {
			t.Fatalf("run %d: output file %q %v", i, b, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "count")); string(b) != "run\n" {
		t.Fatalf("the tool ran %q", b)
	}
	fresh = true
	defer func() { fresh = false }()
	if _, m := run("t", 0x7fffffff, dir, tool, "-o", out); m.Cached {
		t.Fatal("-fresh replayed")
	}
}

// The same tool installed twice, at two times, is one key: parallel CI jobs
// each install their own copy.
func TestRefKeyIgnoresInstallTime(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a", "tool"), filepath.Join(dir, "b", "tool")
	for _, p := range []string{a, b} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("same bytes"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(b, old, old); err != nil {
		t.Fatal(err)
	}
	// refKey hashes the base name, so the two paths differ only in the file's time.
	if x, y := refKey("t", dir, a, []string{"-u", "x"}), refKey("t", dir, b, []string{"-u", "x"}); x != y {
		t.Errorf("keys differ with the install time: %s %s", x, y)
	}
	if err := os.WriteFile(b, []byte("another version"), 0o755); err != nil {
		t.Fatal(err)
	}
	delete(binHashes, b)
	if x, y := refKey("t", dir, a, []string{"-u", "x"}), refKey("t", dir, b, []string{"-u", "x"}); x == y {
		t.Error("another tool binary, the same key")
	}
}
