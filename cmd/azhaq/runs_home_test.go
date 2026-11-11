package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/runs"
)

// folderRun keeps one demo run in a fresh folder with no AZHAQ_HOME and
// a separate empty user home, and returns the folder and that home.
func folderRun(t *testing.T) (folder, userHome string) {
	t.Helper()
	t.Cleanup(egress.Reset)
	t.Setenv("AZHAQ_HOME", "")
	userHome = t.TempDir()
	t.Setenv("HOME", userHome)
	folder = t.TempDir()
	t.Chdir(folder)
	if err := run([]string{"run", "-demo", "-quiet"}); err != nil {
		t.Fatalf("run -demo: %v", err)
	}
	return folder, userHome
}

func TestRunHomeDefaultsToTheWorkingDirectory(t *testing.T) {
	folder, userHome := folderRun(t)
	list, err := runs.List(filepath.Join(folder, ".azhaq"))
	if err != nil || len(list) != 1 {
		t.Fatalf("runs in ./.azhaq: %v %v", list, err)
	}
	dir := filepath.Join(folder, ".azhaq", "runs", list[0].ID)
	for _, f := range []string{"run.json", runs.WorkspaceFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if ents, _ := os.ReadDir(userHome); len(ents) != 0 {
		t.Fatalf("something was written under the user's home: %v", ents)
	}
	if got := readLastDB(); got != list[0].Workspace {
		t.Fatalf("last workspace %q, want %q", got, list[0].Workspace)
	}
}

func TestRunsReadTheFolderYouAreIn(t *testing.T) {
	folder, _ := folderRun(t)
	list, _ := runs.List(filepath.Join(folder, ".azhaq"))
	id := list[0].ID

	out, _, err := captureBoth(t, func() error { return cmdRuns(nil) })
	if err != nil || !strings.Contains(out, id) {
		t.Fatalf("runs in the folder: %v\n%s", err, out)
	}

	other := t.TempDir()
	t.Chdir(other)
	out, errOut, err := captureBoth(t, func() error { return cmdRuns(nil) })
	if err != nil || strings.Contains(out, id) {
		t.Fatalf("runs in another folder: %v\n%s", err, out)
	}
	if !strings.Contains(errOut, "no runs kept in") || !strings.Contains(errOut, "-home DIR") || !strings.Contains(errOut, "AZHAQ_HOME") {
		t.Fatalf("the empty folder is not explained: %q", errOut)
	}
	if err := cmdUI([]string{"-listen", "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "-home DIR") {
		t.Fatalf("ui in a folder with no runs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, ".azhaq")); err == nil {
		t.Fatal("reading made a .azhaq")
	}

	out, _, err = captureBoth(t, func() error { return cmdRuns([]string{"-home", filepath.Join(folder, ".azhaq")}) })
	if err != nil || !strings.Contains(out, id) {
		t.Fatalf("-home from elsewhere: %v\n%s", err, out)
	}
	t.Setenv("AZHAQ_HOME", filepath.Join(folder, ".azhaq"))
	out, _, err = captureBoth(t, func() error { return cmdRuns(nil) })
	if err != nil || !strings.Contains(out, id) {
		t.Fatalf("AZHAQ_HOME from elsewhere: %v\n%s", err, out)
	}
}

func TestQueryWithoutDBInAFolderWithNoRunsSaysSo(t *testing.T) {
	folderRun(t)
	t.Chdir(t.TempDir())
	err := run([]string{"query"})
	if err == nil || !strings.Contains(err.Error(), "no run was kept in this folder") || !strings.Contains(err.Error(), "AZHAQ_HOME") {
		t.Fatalf("query in a folder with no runs: %v", err)
	}
}

// A working directory that cannot hold .azhaq stops the run before it
// sends; a .azhaq that is a file fails the same way for root too.
func TestRunFailsWhereTheFolderCannotKeepItBeforeSending(t *testing.T) {
	t.Cleanup(egress.Reset)
	t.Setenv("AZHAQ_HOME", "")
	t.Setenv("HOME", t.TempDir())
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	folder := t.TempDir()
	t.Chdir(folder)
	if err := os.WriteFile(".azhaq", []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"probe", "-u", srv.URL + "/", "-allow", "127.0.0.1", "-silent"})
	if err == nil {
		t.Fatal("the run went on")
	}
	for _, want := range []string{"cannot keep the run", "-db DIR/x.db", "AZHAQ_HOME"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests were sent", hits.Load())
	}
	if m, _ := filepath.Glob("azhaq-*.db"); len(m) > 0 {
		t.Fatalf("it fell back to a database here: %v", m)
	}

	// -db names where the workspace goes: the run is then not kept, and goes on.
	db := filepath.Join(t.TempDir(), "x.db")
	if err := run([]string{"probe", "-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-silent"}); err != nil {
		t.Fatalf("with -db: %v", err)
	}
	if hits.Load() == 0 {
		t.Fatal("with -db nothing was sent")
	}
}
