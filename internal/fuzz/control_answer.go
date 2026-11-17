package fuzz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// ControlRef is the request calibration (-ac) made for a name that cannot
// exist, and what it answered: a match that is the same answer is marked
// with it.
type ControlRef struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Size   int64  `json:"size"`
}

// controlAnswer is what one calibration request answered, kept to compare
// the matches with: the sum of its bytes, and the sum with the name it asked
// taken out (an error page that echoes the name is the same page for
// another).
type controlAnswer struct {
	ref  ControlRef
	sum  string
	free string // empty when the body was not kept
}

// echoFree is the sum of body with every form of word in it taken out.
func echoFree(body []byte, word string) string {
	if body == nil || word == "" {
		return ""
	}
	s := string(body)
	forms := []string{word, url.PathEscape(word), url.QueryEscape(word)}
	for _, f := range forms {
		s = strings.ReplaceAll(s, f, "\x00")
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// noteControl keeps what a calibration request answered, whether a matcher
// keeps it or not: it is the run's own answer for a name that cannot exist.
func (e *engine) noteControl(key string, req *Request, r *Response, word string) {
	c := controlAnswer{
		ref:  ControlRef{URL: req.URL, Status: r.Status, Size: r.Length},
		sum:  r.Sum,
		free: echoFree(r.Body, word),
	}
	e.shapeMu.Lock()
	e.controls[key] = append(e.controls[key], c)
	e.shapeMu.Unlock()
}

// sameAsControl says which calibration answer r is the same as: the status
// and the bytes of the body, or, when both were kept, the bytes once each
// request's own input is taken out. Nil when -ac was not asked or none is.
func (e *engine) sameAsControl(r *Response, req *Request) *ControlRef {
	if !e.cfg.Calibrate {
		return nil
	}
	key := ""
	if e.cfg.Set.PerHost {
		key = HostKey(req)
	}
	e.shapeMu.RLock()
	cs := e.controls[key]
	e.shapeMu.RUnlock()
	free := echoFree(r.Body, req.Input[e.cfg.CalKeyword])
	for _, c := range cs {
		if c.ref.Status != r.Status {
			continue
		}
		if r.Sum != "" && c.sum == r.Sum || free != "" && c.free == free {
			ref := c.ref
			return &ref
		}
	}
	return nil
}

// prefixAnswer is what a name asked under a match's own path answered: the
// control of the prefix that match opens.
type prefixAnswer struct {
	status int
	free   string // sum of the body with the path asked taken out; empty: no answer
}

// prefixTemplate says a match opens a directory: the keyword ends the path of
// the URL, so word/<random> is a path under it.
func prefixTemplate(t Template, keyword string) bool {
	path, _, _ := strings.Cut(t.URL, "?")
	path, _, _ = strings.Cut(path, "#")
	return strings.HasSuffix(path, keyword) && strings.Count(t.URL, keyword) == 1 &&
		!strings.Contains(t.Method+t.Data, keyword)
}

// pathFree is the sum of the body with the path of requestURL taken out, in
// the forms an error page echoes it; ok is false when the body does not name it.
func pathFree(requestURL string, body []byte) (sum string, ok bool) {
	s := string(body)
	free := fetch.EchoFree(requestURL, s)
	if free == s {
		return "", false
	}
	h := sha256.Sum256([]byte(free))
	return hex.EncodeToString(h[:8]), true
}

// prefixCatchAll says a match is the catch-all of the prefix it opens: its
// answer names its own path and, with that taken out, is the answer of a
// control asked at input/<random>, with the control's path taken out too. The
// control is measured, one for each prefix, and kept for the matches under it;
// the budget refusing it, or its failing, leaves the match listed. A match
// that is already the same as a calibration answer says so by its control.
func (e *engine) prefixCatchAll(ctx context.Context, t Template, input map[string]string, req *Request, r *Response) bool {
	if !e.cfg.Calibrate || !e.prefixOK.Load() || r.Body == nil || r.Status < 300 || !prefixTemplate(t, e.cfg.CalKeyword) {
		return false
	}
	if r.Status >= 300 && r.Status < 400 && fetch.EchoFree(req.URL, r.Header.Get("Location")) == "\x00/" {
		return false // a directory: it redirects to its own path with a slash
	}
	free, ok := pathFree(req.URL, r.Body)
	if !ok || e.sameAsControl(r, req) != nil {
		return false
	}
	e.prefixMu.Lock()
	defer e.prefixMu.Unlock()
	own := req.URL + "/"
	for p, a := range e.prefixes {
		if strings.HasPrefix(own, p) && a.free != "" && a.status == r.Status && a.free == free {
			return true
		}
	}
	if e.prefixes[own] != nil || ctx.Err() != nil || e.stop.Load() {
		return false
	}
	a := &prefixAnswer{}
	e.prefixes[own] = a
	in := make(map[string]string, len(input))
	for k, v := range input {
		in[k] = v
	}
	in[e.cfg.CalKeyword] = input[e.cfg.CalKeyword] + "/" + randomName(12)
	creq := t.Expand(in)
	if !e.inScope(&creq) || e.denied(&creq) {
		return false
	}
	resp, err := e.send(ctx, &creq)
	if err != nil {
		return false
	}
	if cfree, ok := pathFree(creq.URL, resp.Body); ok {
		a.status, a.free = resp.Status, cfree
	}
	return a.free != "" && a.status == r.Status && a.free == free
}
