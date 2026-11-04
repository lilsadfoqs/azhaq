package fetch

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"slices"
	"sort"
	"strings"
)

// Req is a request to a target that is not a plain GET: a method, a body
// and headers that go with this request only (probe -x, -body and -rr).
type Req struct {
	Method string
	Body   []byte
	Header http.Header
	// IP, when set, is the address the connection goes to, whatever the
	// name resolves to (-pa: one request per address of a name).
	IP string
}

func (r *Req) method() string {
	if r == nil || r.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(r.Method)
}

func (r *Req) body() []byte {
	if r == nil {
		return nil
	}
	return r.Body
}

// Plain says r is a GET without a body or headers of its own.
func (r *Req) Plain() bool {
	return r == nil || r.method() == http.MethodGet && len(r.Body) == 0 && len(r.Header) == 0 && r.IP == ""
}

// Key is what the answer to r is kept under.
func (r *Req) Key(raw string) string {
	raw = canonical(raw)
	if r.Plain() {
		return raw
	}
	h := sha256.New()
	h.Write(r.Body)
	h.Write([]byte("ip=" + r.IP))
	var names []string
	for k := range r.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		h.Write([]byte(k + ":" + strings.Join(r.Header[k], ",") + "\n"))
	}
	return r.method() + " " + raw + " #" + hex.EncodeToString(h.Sum(nil)[:6])
}

func (r *Req) apply(req *http.Request) {
	if r == nil {
		return
	}
	for k, vs := range r.Header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if h := req.Header.Get("Host"); h != "" {
		req.Host = h
		req.Header.Del("Host")
	}
}

// Raw is a request and the last response as they went over the wire.
type Raw struct {
	Request []byte   `json:"request,omitempty"` // the first request, headers and body
	Head    string   `json:"head,omitempty"`    // the last response's status line and headers
	Proto   string   `json:"proto,omitempty"`
	TLS     *TLSInfo `json:"tls,omitempty"`
	Chain   []RawHop `json:"chain,omitempty"` // each hop of a followed redirect
}

// RawHop is one request of a redirect chain and the head of its answer.
type RawHop struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

// TLSInfo is what the handshake of the last response gave.
type TLSInfo struct {
	Version    uint16   `json:"version"`
	Cipher     uint16   `json:"cipher"`
	ServerName string   `json:"server_name,omitempty"`
	Certs      [][]byte `json:"certs,omitempty"` // DER, leaf first
}

func tlsInfo(cs *tls.ConnectionState) *TLSInfo {
	if cs == nil {
		return nil
	}
	t := &TLSInfo{Version: cs.Version, Cipher: cs.CipherSuite, ServerName: cs.ServerName}
	for _, c := range cs.PeerCertificates {
		t.Certs = append(t.Certs, c.Raw)
	}
	return t
}

// dumpRequest is req as it goes out, with its body.
func dumpRequest(req *http.Request, body []byte) []byte {
	cp := req.Clone(context.Background()) // not the trace: the dump sends nothing
	if len(body) > 0 {
		cp.Body = nopCloser(body)
	}
	d, err := httputil.DumpRequestOut(cp, true)
	if err != nil {
		return nil
	}
	return d
}

type bodyReader struct{ *strings.Reader }

func (bodyReader) Close() error { return nil }

func nopCloser(b []byte) bodyReader { return bodyReader{strings.NewReader(string(b))} }

// SecretHeader says whether a header's name sounds like a credential
// (Authorization, Cookie, X-Api-Key, a token, a session, a CSRF value): what
// is kept in a workspace is kept without such headers.
func SecretHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, w := range []string{"auth", "cookie", "token", "key", "session", "secret", "csrf", "xsrf"} {
		if strings.Contains(name, w) {
			return true
		}
	}
	return false
}

// scrubRequest is a request as it went over the wire, without its
// credential headers and its body: the line and the other headers.
func scrubRequest(wire string) string {
	head, _, _ := strings.Cut(wire, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	out := lines[:1]
	for _, l := range lines[1:] {
		if name, _, _ := strings.Cut(l, ":"); !SecretHeader(name) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\r\n") + "\r\n\r\n"
}

// Scrubbed is a copy of r whose requests keep no credential header and no
// body: it is what a workspace stores of an answer.
func (r *Raw) Scrubbed() *Raw {
	if r == nil {
		return nil
	}
	c := *r
	if len(c.Request) > 0 {
		c.Request = []byte(scrubRequest(string(c.Request)))
	}
	c.Chain = slices.Clone(r.Chain)
	for i := range c.Chain {
		c.Chain[i].Request = scrubRequest(c.Chain[i].Request)
	}
	return &c
}
