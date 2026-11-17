package paramcol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"sort"

	"github.com/lilsadfoqs/azhaq/internal/fuzz"
)

// exchange is a request and the answer the comparison already read. It is
// built only with KeepDir, and a name's file is written from it when the
// name is reported: no request is repeated to get it.
type exchange struct {
	req           *http.Request
	proto, status string
	hdr           http.Header
	body          []byte
	cut           bool // the read stopped short of the body (a stream, or past 2 MiB)
}

// write puts the exchange in dir as fuzz -od does and returns the file's
// name, and whether its body ends at the cap.
func (e *exchange) write(dir string) (string, bool, error) {
	var rawReq []byte
	if e.req != nil {
		// A clone: the run's context may be over, and Do consumed the body.
		r := e.req.Clone(context.Background())
		if e.req.GetBody != nil {
			r.Body, _ = e.req.GetBody()
		}
		rawReq, _ = httputil.DumpRequestOut(r, true)
	}
	body := e.body[:min(len(e.body), fuzz.MaxBody)]
	resp := fmt.Sprintf("%s %s\r\n", e.proto, e.status)
	var h headerText
	_ = e.hdr.Write(&h)
	resp += string(h) + "\r\n" + string(body)
	name, err := fuzz.KeepExchange(dir, string(rawReq), resp)
	return name, e.cut || len(e.body) > len(body), err
}

type headerText []byte

func (h *headerText) Write(p []byte) (int, error) { *h = append(*h, p...); return len(p), nil }

// keepFiles writes the file of each reported name that has an exchange and
// sets the row's resultfile (name → file) and resultfile_cut (names whose
// body ends at the cap). It returns how many files could not be written.
// The exchanges are dropped: no body outlives the row.
func (s *search) keepFiles(row map[string]any, found map[string]string) int {
	s.mu.Lock()
	kept := s.kept
	s.kept = nil
	s.mu.Unlock()
	type wrote struct {
		file string
		cut  bool
		err  error
	}
	done := map[*exchange]wrote{} // names of one group share its request
	files := map[string]string{}
	var cut []string
	failed := 0
	for n := range found {
		ex := kept[n]
		if ex == nil {
			continue
		}
		w, ok := done[ex]
		if !ok {
			w.file, w.cut, w.err = ex.write(s.c.Opts.KeepDir)
			done[ex] = w
		}
		if w.err != nil {
			failed++
			continue
		}
		files[n] = w.file
		if w.cut {
			cut = append(cut, n)
		}
	}
	if len(files) > 0 {
		row["resultfile"] = files
	}
	if len(cut) > 0 {
		sort.Strings(cut)
		row["resultfile_cut"] = cut
	}
	return failed
}

// remember keeps the exchange that showed name until the page's row is
// given. Only a name that is reported gets here (see gather).
func (s *search) remember(name string, ex *exchange) {
	if ex == nil {
		return
	}
	s.mu.Lock()
	if s.kept == nil {
		s.kept = map[string]*exchange{}
	}
	s.kept[name] = ex
	s.mu.Unlock()
}
