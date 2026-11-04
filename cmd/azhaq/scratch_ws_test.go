package main

import (
	"path/filepath"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/dirscol"
)

// A command that keeps no workspace (dirs, probe, ports and the rest that run
// through runPreset) works in a scratch one, which makes nothing durable; one
// that is given -db keeps an ordinary workspace.
func TestAOneShotCommandWorksInAScratchWorkspace(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 403})
	list, rm, err := tempList([]string{srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer rm()
	args := []string{"-list", list, "-depth", "1", "-no-tech", "-no-favicon", "-skip", skipAllBut("azhaq-dns", "azhaq-dirs"), "-dirs", dirscol.Builtin, "-allow", "127.0.0.1", "-quiet"}
	for _, c := range []struct {
		name string
		db   string
		want bool
	}{{"no -db", "", true}, {"-db given", filepath.Join(t.TempDir(), "ws.db"), false}} {
		st, done, err := runPreset(&common{db: c.db, silent: true}, args, newReport("dirs"), nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if st.Scratch() != c.want {
			t.Errorf("%s: scratch workspace %v, want %v", c.name, st.Scratch(), c.want)
		}
		done()
	}
}
