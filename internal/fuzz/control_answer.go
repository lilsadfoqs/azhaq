package fuzz

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
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
