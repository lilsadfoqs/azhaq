package browser

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
)

// credentials are what the run gave the sign-in: the request that carries
// either is the sign-in, and it is the only write the sign-in's tab sends
// without -browser-writes. A navigation of the tab's own page posting its
// form after the form was submitted is the other.
type credentials struct {
	user, pass string
	submitted  atomic.Bool // the form was submitted by the sign-in
}

// signsIn says whether a write of the sign-in's tab is the sign-in: its
// form posted as a navigation of the page, after the form was submitted,
// or a request that carries the user name or the password the run gave in
// its URL, its headers (also as Basic auth) or its body. A request whose
// body is not exposed by Chrome (hasPostData without the data) is not
// known to carry them. Never a guess about the route: a script's polling
// POST or beacon carries neither.
func (c *credentials) signsIn(req *network.Request, doc bool, frame, main cdp.FrameID) bool {
	if c == nil || req == nil {
		return false
	}
	if doc && frame == main && c.submitted.Load() {
		return true
	}
	return c.carry(req)
}

func (c *credentials) carry(req *network.Request) bool {
	has := func(s string) bool {
		return c.pass != "" && strings.Contains(s, c.pass) || c.user != "" && strings.Contains(s, c.user)
	}
	if u, err := url.Parse(req.URL); err == nil && (has(u.RawQuery) || hasValue(u.Query(), has)) {
		return true
	}
	for k, v := range req.Headers {
		s, _ := v.(string)
		switch strings.ToLower(k) {
		case "cookie", "referer", "origin", "host":
			continue
		}
		if has(s) || has(decoded(s)) {
			return true
		}
	}
	var body []byte
	for _, e := range req.PostDataEntries {
		if e != nil {
			body = append(body, e.Bytes...)
		}
	}
	return bodyHas(string(body), header(req.Headers, "Content-Type"), has)
}

func hasValue(q url.Values, has func(string) bool) bool {
	for _, vs := range q {
		for _, v := range vs {
			if has(v) {
				return true
			}
		}
	}
	return false
}

// decoded is the base64 a header value holds, after an auth scheme: Basic
// carries user:password.
func decoded(v string) string {
	if _, rest, ok := strings.Cut(v, " "); ok {
		v = rest
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(strings.TrimSpace(v)); err == nil {
			return string(b)
		}
	}
	return ""
}

// bodyHas looks for a value in a body as it was sent and as its media
// type escapes it: the raw bytes, a form's decoded fields, a JSON string
// (a password with a quote or a backslash is escaped in the raw bytes),
// a multipart part.
func bodyHas(body, contentType string, has func(string) bool) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	if has(body) {
		return true
	}
	if s, err := url.QueryUnescape(body); err == nil && has(s) {
		return true
	}
	media, params, _ := mime.ParseMediaType(contentType)
	if media == "multipart/form-data" && params["boundary"] != "" {
		r := multipart.NewReader(strings.NewReader(body), params["boundary"])
		for {
			p, err := r.NextPart()
			if err != nil {
				break
			}
			if b, err := io.ReadAll(io.LimitReader(p, maxBody)); err == nil && has(string(b)) {
				return true
			}
		}
	}
	var v any
	return json.Unmarshal([]byte(body), &v) == nil && jsonHas(v, has)
}

func jsonHas(v any, has func(string) bool) bool {
	switch x := v.(type) {
	case string:
		return has(x)
	case []any:
		for _, e := range x {
			if jsonHas(e, has) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if jsonHas(e, has) {
				return true
			}
		}
	}
	return false
}
