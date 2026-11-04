package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func pragma(t *testing.T, s *Store, name string) int {
	t.Helper()
	var v int
	if err := s.db.QueryRow(`PRAGMA ` + name).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A workspace that is deleted when its command ends has nothing to make
// durable: no fsync. One a user keeps stays at NORMAL.
func TestScratchWorkspaceIsNotMadeDurable(t *testing.T) {
	dir := t.TempDir()
	kept, err := Open(filepath.Join(dir, "kept.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	scratch, err := OpenScratch(filepath.Join(dir, "scratch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	if got := pragma(t, kept, "synchronous"); got != 1 || kept.Scratch() {
		t.Errorf("a kept workspace: synchronous %d (want 1, NORMAL), scratch %v", got, kept.Scratch())
	}
	if got := pragma(t, scratch, "synchronous"); got != 0 || !scratch.Scratch() {
		t.Errorf("a scratch workspace: synchronous %d (want 0, OFF), scratch %v", got, scratch.Scratch())
	}
	// It is still a whole workspace: a run can be written to it and read back.
	if err := scratch.BeginRun("r1", 1, 1); err != nil {
		t.Fatal(err)
	}
	if runs, err := scratch.Runs(); err != nil || len(runs) != 1 {
		t.Errorf("runs of a scratch workspace: %v, %v", runs, err)
	}
	again, err := OpenExistingScratch(filepath.Join(dir, "scratch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !again.Scratch() {
		t.Error("OpenExistingScratch did not open a scratch workspace")
	}
}

// The schema is made once: a workspace is stamped when it is whole, and the
// next open runs none of the statements that make it.
func TestAWholeWorkspaceIsNotMigratedAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := pragma(t, s, "user_version"); got != schemaVersion {
		t.Fatalf("a new workspace is stamped %d, want %d", got, schemaVersion)
	}
	if _, err := s.db.Exec(`DROP TABLE spend`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'spend'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a stamped workspace was migrated again: spend table found %d times (%v)", n, err)
	}
}

// A workspace made before the stamp, with the older columns missing, is
// brought up to date and stamped on its first open.
func TestAnOlderWorkspaceIsMigratedAndStamped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE runs (id TEXT PRIMARY KEY, started INTEGER NOT NULL, capped INTEGER NOT NULL DEFAULT 0, depth INTEGER NOT NULL DEFAULT 0, max_items INTEGER NOT NULL DEFAULT 0);
CREATE TABLE observations (id TEXT PRIMARY KEY, entity_id TEXT NOT NULL, collector TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, confidence REAL NOT NULL, observed_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := pragma(t, s, "user_version"); got != schemaVersion {
		t.Errorf("an older workspace is stamped %d after its first open, want %d", got, schemaVersion)
	}
	for _, col := range []struct{ table, name string }{{"observations", "run_id"}, {"runs", "args"}, {"runs", "requests"}} {
		var n int
		q := `SELECT COUNT(*) FROM pragma_table_info('` + col.table + `') WHERE name = '` + col.name + `'`
		if err := s.db.QueryRow(q).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s.%s after the first open: %d (%v)", col.table, col.name, n, err)
		}
	}
}
