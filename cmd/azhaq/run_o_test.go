package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run -o FILE writes the rows run prints, as crawl, probe and ports do:
// with -json the JSON lines, without the text map; the summary lists the
// file under wrote.
func TestRunWritesItsRowsToO(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DATA_DIR", dir)
	for _, asJSON := range []bool{true, false} {
		file := filepath.Join(dir, "map.txt")
		args := []string{"run", "-demo", "-db", "r.db", "-o", file}
		if asJSON {
			args = append(args, "-json")
		}
		out, errOut, code := cli(t, args...)
		if code != exitOK {
			t.Fatalf("json=%v: exit %d\n%s", asJSON, code, errOut)
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("json=%v: %v", asJSON, err)
		}
		if string(raw) != out || len(raw) == 0 {
			t.Errorf("json=%v: the file holds %d bytes, stdout %d:\n%s", asJSON, len(raw), len(out), raw)
		}
		if asJSON && !strings.HasPrefix(string(raw), "{") {
			t.Errorf("-json: the file is not JSON lines: %.80s", raw)
		}
		if !strings.Contains(errOut, file) {
			t.Errorf("json=%v: the summary does not list %s: %s", asJSON, file, errOut)
		}
	}
	// The summary says it as a field.
	_, errOut, _ := cli(t, "run", "-demo", "-db", "r2.db", "-o", "m.jsonl", "-json")
	if wrote, _ := sumMap(t, errOut)["wrote"].([]any); !containsAny(wrote, "m.jsonl") {
		t.Errorf("wrote = %v", wrote)
	}
}

func containsAny(xs []any, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// -quiet prints nothing; the file the user named still gets the rows. A
// directory, or a file that cannot be made, fails before anything is sent.
func TestRunOWithQuietAndBadPaths(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DATA_DIR", dir)
	out, errOut, code := cli(t, "run", "-demo", "-db", "q.db", "-quiet", "-json", "-o", "q.jsonl")
	if code != exitOK || out != "" {
		t.Fatalf("exit %d, stdout %q\n%s", code, out, errOut)
	}
	if raw, err := os.ReadFile("q.jsonl"); err != nil || len(raw) == 0 {
		t.Errorf("-quiet -o: %v, %d bytes", err, len(raw))
	}
	if _, errOut, code := cli(t, "run", "-demo", "-db", "d.db", "-o", dir); code != exitUsage || !strings.Contains(errOut, "is a directory") {
		t.Errorf("a directory: exit %d\n%s", code, errOut)
	}
	if _, errOut, code := cli(t, "run", "-demo", "-db", "e.db", "-o", filepath.Join(dir, "no", "such", "dir", "f")); code != exitError {
		t.Errorf("an unwritable path: exit %d\n%s", code, errOut)
	}
}
