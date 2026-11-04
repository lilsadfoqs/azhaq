package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// isolate points the home, the XDG and the temporary directories at empty
// folders, leaves $AZHAQ_DATA_DIR unset, and works in an empty folder. It
// returns the folders to look in afterwards and the workspace.
func isolate(t *testing.T) (outside []string, work string) {
	t.Helper()
	home, cfg, data, cache, tmp := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("AZHAQ_DATA_DIR", "")
	work = t.TempDir()
	t.Chdir(work)
	return []string{home, cfg, data, cache, tmp}, work
}

func filesUnder(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// A subs run writes its name history inside the folder it works in, names
// the file, and writes nothing under the home, XDG or temporary directories.
func TestSubsWritesInsideItsWorkspace(t *testing.T) {
	outside, work := isolate(t)
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "api.example.org"}},
		subcol.TestSource{Name: "history", Default: true})()
	_, errOut, err := captureBoth(t, func() error { return run([]string{"subs", "-d", "example.org", "-json"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	hist := filepath.Join("azhaq-data", "names", "example.org.json")
	if _, err := os.Stat(filepath.Join(work, hist)); err != nil {
		t.Fatalf("no history in the workspace: %v", err)
	}
	if !slices.Contains(rep.Wrote, hist) {
		t.Errorf("the summary says it wrote %v, not %s", rep.Wrote, hist)
	}
	for _, d := range outside {
		if f := filesUnder(d); len(f) != 0 {
			t.Errorf("%s was written to: %v", d, f)
		}
	}
	// Every file the workspace holds is one the summary names.
	for _, f := range filesUnder(work) {
		rel, _ := filepath.Rel(work, f)
		if !slices.Contains(rep.Wrote, rel) {
			t.Errorf("%s was written and the summary does not name it (%v)", rel, rep.Wrote)
		}
	}
}

// With -db the history sits beside the database; a history is shared only
// when the user names it, by -history-dir or $AZHAQ_DATA_DIR.
func TestHistoryIsSharedOnlyWhenNamed(t *testing.T) {
	outside, work := isolate(t)
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org"}},
		subcol.TestSource{Name: "history", Default: true})()
	sub := filepath.Join(work, "engagement")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	runSubs := func(extra ...string) report {
		t.Helper()
		_, errOut, err := captureBoth(t, func() error {
			return run(append([]string{"subs", "-d", "example.org", "-json"}, extra...))
		})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return lastReport(t, errOut)
	}
	runSubs("-db", filepath.Join(sub, "ws.db"))
	if _, err := os.Stat(filepath.Join(sub, "azhaq-data", "names", "example.org.json")); err != nil {
		t.Errorf("not beside -db: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, "azhaq-data")); err == nil {
		t.Error("the current directory got a history for a run whose database is elsewhere")
	}
	shared := t.TempDir()
	rep := runSubs("-db", filepath.Join(sub, "ws2.db"), "-history-dir", shared)
	if _, err := os.Stat(filepath.Join(shared, "names", "example.org.json")); err != nil {
		t.Errorf("-history-dir ignored: %v", err)
	}
	if !slices.Contains(rep.Wrote, filepath.Join(shared, "names", "example.org.json")) {
		t.Errorf("wrote %v", rep.Wrote)
	}
	envDir := t.TempDir()
	t.Setenv("AZHAQ_DATA_DIR", envDir)
	runSubs("-db", filepath.Join(sub, "ws3.db"))
	if _, err := os.Stat(filepath.Join(envDir, "names", "example.org.json")); err != nil {
		t.Errorf("$AZHAQ_DATA_DIR ignored: %v", err)
	}
	for _, d := range outside {
		if f := filesUnder(d); len(f) != 0 {
			t.Errorf("%s was written to: %v", d, f)
		}
	}
	_ = strings.TrimSpace
}

// A run of a web target writes in its workspace only, and the summary names
// every file it wrote besides the database.
func TestRunWritesInsideItsWorkspace(t *testing.T) {
	outside, work := isolate(t)
	srv, _ := juiceShop(t)
	db := filepath.Join(work, "ws.db")
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none", "-quiet", "-json", "-db", db})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	for _, d := range outside {
		if f := filesUnder(d); len(f) != 0 {
			t.Errorf("%s was written to: %v", d, f)
		}
	}
	for _, f := range filesUnder(work) {
		if f == db || strings.HasPrefix(f, db+"-") {
			continue // the database and its journal
		}
		if !slices.Contains(rep.Wrote, f) {
			t.Errorf("%s was written and the summary does not name it (%v)", f, rep.Wrote)
		}
	}
	if !slices.Contains(rep.Wrote, db+".ledger.jsonl") {
		t.Errorf("the ledger is not named: %v", rep.Wrote)
	}
}

// A run with a new database of its own remembers it in .azhaq-last and
// .azhaq-index, in the current directory, and says so.
func TestRunNamesThePointersItWrites(t *testing.T) {
	outside, work := isolate(t)
	srv, _ := juiceShop(t)
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none", "-quiet", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	for _, want := range []string{lastDBFile, runIndexFile} {
		if !slices.Contains(rep.Wrote, want) {
			t.Errorf("%s is not named: %v", want, rep.Wrote)
		}
	}
	for _, f := range filesUnder(work) {
		rel, _ := filepath.Rel(work, f)
		if rel != rep.DB && !strings.HasPrefix(rel, rep.DB+"-") && !slices.Contains(rep.Wrote, rel) {
			t.Errorf("%s was written and the summary does not name it (%v)", rel, rep.Wrote)
		}
	}
	for _, d := range outside {
		if f := filesUnder(d); len(f) != 0 {
			t.Errorf("%s was written to: %v", d, f)
		}
	}
}
