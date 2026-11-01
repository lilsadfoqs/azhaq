package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"
)

// Evidence is what stands behind the rows azhaq roles listed: each role's
// answer to each row, kept so that a row can be checked and asked again
// by hand (azhaq roles show).
type Evidence struct {
	db *sql.DB
	// legacy: the file was made before rows were kept by owner. Reading it
	// works (one row for each URL and method); saving replaces its tables.
	legacy bool
}

// EvidenceRow is one listed row: the row as roles -json prints it, and the
// answers behind it. Owner is the role whose object or request it is: two
// owners' POSTs to one collection are two rows.
type EvidenceRow struct {
	URL, Method, Owner string
	Row                []byte
	Answers            []EvidenceAnswer
}

// EvidenceAnswer is one role's answer: to the row's URL, or, for a
// control, to a made-up identifier on the same route (Asked).
type EvidenceAnswer struct {
	Role        string
	Kind        string // "answer" or "control"
	Asked       string // the URL asked
	Status      int
	Length      int // of the body as answered, before it was cut or redacted
	ContentType string
	Curl        string // the request, with the role's session as placeholders
	Body        []byte // as kept: cut, sensitive values taken out
	Truncated   bool
}

// OpenEvidence opens (or makes) the evidence database at path.
func OpenEvidence(path string) (*Evidence, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	e := &Evidence{db: db}
	if err := e.schema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return e, nil
}

const evidenceTables = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rows (
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  row TEXT NOT NULL,
  PRIMARY KEY (url, method, owner)
);
CREATE TABLE IF NOT EXISTS answers (
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL,
  kind TEXT NOT NULL,
  asked TEXT NOT NULL,
  status INTEGER NOT NULL,
  length INTEGER NOT NULL DEFAULT 0,
  content_type TEXT NOT NULL,
  curl TEXT NOT NULL,
  body BLOB,
  truncated INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (url, method, owner, role, kind)
);`

// schema makes the tables, and notes a file made before rows had an owner.
func (e *Evidence) schema() error {
	if _, err := e.db.Exec(evidenceTables); err != nil {
		return err
	}
	rs, err := e.db.Query(`PRAGMA table_info(rows)`)
	if err != nil {
		return err
	}
	defer rs.Close()
	has := false
	for rs.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rs.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		has = has || name == "owner"
	}
	e.legacy = !has
	return rs.Err()
}

// OpenEvidenceExisting opens an evidence database that must exist.
func OpenEvidenceExisting(path string) (*Evidence, error) {
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		return nil, fmt.Errorf("no evidence at %s", path)
	}
	return OpenEvidence(path)
}

func (e *Evidence) Close() error { return e.db.Close() }

// Save replaces what the database holds with rows, of the roles named in
// order.
func (e *Evidence) Save(roles []string, rows []EvidenceRow) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if e.legacy {
		for _, q := range []string{`DROP TABLE rows`, `DROP TABLE answers`, evidenceTables} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
	}
	for _, q := range []string{`DELETE FROM rows`, `DELETE FROM answers`} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('roles', ?)`, strings.Join(roles, "\n")); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta (k, v) VALUES ('saved_at', ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	insRow, err := tx.Prepare(`INSERT OR REPLACE INTO rows (url, method, owner, row) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insRow.Close()
	insAns, err := tx.Prepare(`INSERT OR REPLACE INTO answers (url, method, owner, role, kind, asked, status, length, content_type, curl, body, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insAns.Close()
	for _, r := range rows {
		if _, err := insRow.Exec(r.URL, r.Method, r.Owner, string(r.Row)); err != nil {
			return err
		}
		for _, a := range r.Answers {
			var body []byte
			if a.Body != nil {
				body = gz(a.Body)
			}
			cut := 0
			if a.Truncated {
				cut = 1
			}
			if _, err := insAns.Exec(r.URL, r.Method, r.Owner, a.Role, a.Kind, a.Asked, a.Status, a.Length, a.ContentType, a.Curl, body, cut); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	e.legacy = false
	return nil
}

// Roles are the roles of the run, in the order they were given.
func (e *Evidence) Roles() []string {
	var v string
	if e.db.QueryRow(`SELECT v FROM meta WHERE k = 'roles'`).Scan(&v) != nil || v == "" {
		return nil
	}
	return strings.Split(v, "\n")
}

// SavedAt is when the run saved the evidence; not ok for a database an
// older version wrote.
func (e *Evidence) SavedAt() (time.Time, bool) {
	var v string
	if e.db.QueryRow(`SELECT v FROM meta WHERE k = 'saved_at'`).Scan(&v) != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	return t, err == nil
}

// Rows are the rows kept for url and method ("" for a read), one for each
// owner, by owner name; none when there is no such row.
func (e *Evidence) Rows(url, method string) ([]EvidenceRow, error) {
	col := "owner"
	if e.legacy {
		col = "''"
	}
	rs, err := e.db.Query(`SELECT `+col+`, row FROM rows WHERE url = ? AND method = ? ORDER BY 1`, url, method)
	if err != nil {
		return nil, err
	}
	var out []EvidenceRow
	for rs.Next() {
		r := EvidenceRow{URL: url, Method: method}
		var row string
		if err := rs.Scan(&r.Owner, &row); err != nil {
			_ = rs.Close()
			return nil, err
		}
		r.Row = []byte(row)
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		_ = rs.Close()
		return nil, err
	}
	_ = rs.Close()
	for i := range out {
		if out[i].Answers, err = e.answers(out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (e *Evidence) answers(r EvidenceRow) ([]EvidenceAnswer, error) {
	q := `SELECT role, kind, asked, status, length, content_type, curl, body, truncated FROM answers WHERE url = ? AND method = ?`
	args := []any{r.URL, r.Method}
	if !e.legacy {
		q += ` AND owner = ?`
		args = append(args, r.Owner)
	}
	rs, err := e.db.Query(q+` ORDER BY kind, role`, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []EvidenceAnswer
	for rs.Next() {
		var a EvidenceAnswer
		var body []byte
		var cut int
		if err := rs.Scan(&a.Role, &a.Kind, &a.Asked, &a.Status, &a.Length, &a.ContentType, &a.Curl, &body, &cut); err != nil {
			return nil, err
		}
		if body != nil {
			if a.Body, err = gunzip(body); err != nil {
				return nil, err
			}
		}
		a.Truncated = cut == 1
		out = append(out, a)
	}
	return out, rs.Err()
}

// Keys are the URLs and methods kept, as METHOD URL ("GET" for a read).
func (e *Evidence) Keys() ([]string, error) {
	rs, err := e.db.Query(`SELECT DISTINCT method, url FROM rows ORDER BY url, method`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var m, u string
		if err := rs.Scan(&m, &u); err != nil {
			return nil, err
		}
		if m == "" {
			m = "GET"
		}
		out = append(out, m+" "+u)
	}
	return out, rs.Err()
}
