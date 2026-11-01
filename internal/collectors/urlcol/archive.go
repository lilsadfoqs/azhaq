package urlcol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// The workspace keeps one example of each URL shape in its graph; every
// other URL the archives gave is kept in a list beside it, one JSON object a
// line ({"run","url","source"}), written as the pages arrive so a stopped
// run keeps what it read. A resumed run appends to it.

// ArchivePath is the list that goes with the workspace db.
func ArchivePath(db string) string { return db + ".urls.jsonl" }

type archiveLine struct {
	Run    string `json:"run"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

func (c *Collector) archiveOn() bool { return c.opts.Archive != "" && c.opts.RunID != "" }

// appendArchive adds lines (each already ending in a newline) in one write,
// so lines of domains that run together do not mix.
func (c *Collector) appendArchive(lines []byte) error {
	if len(lines) == 0 {
		return nil
	}
	c.outMu.Lock()
	defer c.outMu.Unlock()
	f, err := os.OpenFile(c.opts.Archive, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(lines); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (c *Collector) archiveLine(buf *bytes.Buffer, u, source string) {
	raw, _ := json.Marshal(archiveLine{Run: c.opts.RunID, URL: u, Source: source})
	buf.Write(raw)
	buf.WriteByte('\n')
}

// ReadArchive gives fn each URL the list at path holds for run, as often as
// it was written (a resumed run may ask a domain again). A list that does
// not exist holds none.
func ReadArchive(path, run string, fn func(url, source string)) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var l archiveLine
			if json.Unmarshal(line, &l) == nil && l.Run == run && l.URL != "" {
				fn(l.URL, l.Source)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
