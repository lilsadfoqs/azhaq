package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Two owners' requests to one URL and method are two rows, each with its
// own answers.
func TestEvidenceKeepsARowForEachOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.db")
	ev, err := OpenEvidence(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	mk := func(owner string) EvidenceRow {
		return EvidenceRow{URL: "http://h/books", Method: "POST", Owner: owner, Row: []byte(`{"owner":"` + owner + `"}`),
			Answers: []EvidenceAnswer{{Role: "bob", Kind: "answer", Asked: "http://h/books", Status: 200, Curl: "curl " + owner}}}
	}
	if err := ev.Save([]string{"alice", "bob"}, []EvidenceRow{mk("alice"), mk("carol")}); err != nil {
		t.Fatal(err)
	}
	rows, err := ev.Rows("http://h/books", "POST")
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %+v", err, rows)
	}
	for i, owner := range []string{"alice", "carol"} {
		if rows[i].Owner != owner || len(rows[i].Answers) != 1 || rows[i].Answers[0].Curl != "curl "+owner {
			t.Errorf("row %d: %+v", i, rows[i])
		}
	}
	if keys, _ := ev.Keys(); len(keys) != 1 {
		t.Errorf("keys %v", keys)
	}
}

// A file made before rows had an owner is still read, one row for each URL
// and method, and a save replaces it.
func TestEvidenceReadsAFileWithoutOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
		`CREATE TABLE rows (url TEXT NOT NULL, method TEXT NOT NULL, row TEXT NOT NULL, PRIMARY KEY (url, method))`,
		`CREATE TABLE answers (url TEXT NOT NULL, method TEXT NOT NULL, role TEXT NOT NULL, kind TEXT NOT NULL, asked TEXT NOT NULL, status INTEGER NOT NULL, length INTEGER NOT NULL DEFAULT 0, content_type TEXT NOT NULL, curl TEXT NOT NULL, body BLOB, truncated INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (url, method, role, kind))`,
		`INSERT INTO rows VALUES ('http://h/a', '', '{}')`,
		`INSERT INTO answers VALUES ('http://h/a', '', 'bob', 'answer', 'http://h/a', 200, 0, '', 'curl', NULL, 0)`,
	} {
		if _, err := old.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()
	ev, err := OpenEvidenceExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	rows, err := ev.Rows("http://h/a", "")
	if err != nil || len(rows) != 1 || len(rows[0].Answers) != 1 {
		t.Fatalf("%v %+v", err, rows)
	}
	if err := ev.Save(nil, []EvidenceRow{{URL: "http://h/b", Owner: "alice", Row: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	if rows, err := ev.Rows("http://h/b", ""); err != nil || len(rows) != 1 || rows[0].Owner != "alice" {
		t.Fatalf("after a save: %v %+v", err, rows)
	}
}
