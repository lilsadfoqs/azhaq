package store

import (
	"bytes"
	"compress/gzip"
	"io"
	"sync"
)

// Response is one answer a run got from a target: azhaq resume reads it
// back instead of asking again. Meta is the answer without its body.
type Response struct {
	URL  string
	Meta []byte
	Body []byte
}

// SaveResponses records answers of the current run, a few hundred to a
// transaction: the store is not held for a sweep's thousands at once.
func (s *Store) SaveResponses(rs []Response) error {
	const chunk = 256
	for len(rs) > 0 {
		n := min(len(rs), chunk)
		if err := s.saveResponses(rs[:n]); err != nil {
			return err
		}
		rs = rs[n:]
	}
	return nil
}

func (s *Store) saveResponses(rs []Response) error {
	packed := make([][]byte, len(rs))
	for i, r := range rs {
		packed[i] = gz(r.Body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID == "" {
		return nil
	}
	tx, commit, rollback, err := s.begin()
	if err != nil {
		return err
	}
	defer rollback()
	ins, err := tx.Prepare(`INSERT OR REPLACE INTO responses (run_id, url, meta, body) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for i, r := range rs {
		if _, err := ins.Exec(s.runID, r.URL, string(r.Meta), packed[i]); err != nil {
			return err
		}
	}
	return commit()
}

// LoadResponse is the current run's recorded answer for url.
func (s *Store) LoadResponse(url string) (Response, bool) {
	s.mu.Lock()
	run := s.runID
	s.mu.Unlock()
	var meta string
	var body []byte
	err := s.db.QueryRow(`SELECT meta, body FROM responses WHERE run_id = ? AND url = ?`, run, url).Scan(&meta, &body)
	if err != nil {
		return Response{}, false
	}
	raw, err := gunzip(body)
	if err != nil {
		return Response{}, false
	}
	return Response{URL: url, Meta: []byte(meta), Body: raw}, true
}

// DropResponse forgets the answer recorded for url in the current run, so
// that a resume asks it again.
func (s *Store) DropResponse(url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.q().Exec(`DELETE FROM responses WHERE run_id = ? AND url = ?`, s.runID, url)
	return err
}

// DropResponses forgets the answers recorded for every run but keep: they
// only serve a run that azhaq resume may still continue.
func (s *Store) DropResponses(keep string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.q().Exec(`DELETE FROM responses WHERE run_id <> ?`, keep)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		_, _ = s.q().Exec(`PRAGMA incremental_vacuum`)
	}
	return nil
}

var gzWriters = sync.Pool{New: func() any {
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return w
}}

// packed remembers the last few bodies packed: a site that answers many
// paths with one page is packed once, not once per path.
var packed struct {
	sync.Mutex
	body, gz [4][]byte
	next     int
}

func gz(b []byte) []byte {
	if len(b) >= 1<<10 {
		packed.Lock()
		for i, p := range packed.body {
			if len(p) == len(b) && bytes.Equal(p, b) {
				out := packed.gz[i]
				packed.Unlock()
				return out
			}
		}
		packed.Unlock()
	}
	var buf bytes.Buffer
	w := gzWriters.Get().(*gzip.Writer) // a writer is about 1 MB of tables: reused, not allocated per body
	w.Reset(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	gzWriters.Put(w)
	out := buf.Bytes()
	if len(b) >= 1<<10 {
		packed.Lock()
		packed.body[packed.next], packed.gz[packed.next] = b, out
		packed.next = (packed.next + 1) % len(packed.body)
		packed.Unlock()
	}
	return out
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
