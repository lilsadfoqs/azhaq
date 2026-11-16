package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A proxy that adds its own Server, Via or X-Cache to every answer makes the
// target look like the proxy's software. The run asks the proxy once for its
// own answer, and a header of a target's answer that equals one of the proxy's
// is not read as the target's. Nothing is inferred: only a value seen in the
// proxy's own answer is dropped.

// notIdentity are the X- headers that state a policy or a request's own
// identity, not software: a proxy adding one does not name a product.
var notIdentity = map[string]bool{
	"X-Frame-Options": true, "X-Content-Type-Options": true, "X-Xss-Protection": true,
	"X-Download-Options": true, "X-Permitted-Cross-Domain-Policies": true, "X-Ua-Compatible": true,
	"X-Dns-Prefetch-Control": true, "X-Robots-Tag": true, "X-Request-Id": true,
}

// IdentityHeader says a header names software or an intermediary: what the
// detection reads to name a product or a cache.
func IdentityHeader(name string) bool {
	n := http.CanonicalHeaderKey(name)
	switch n {
	case "Server", "X-Powered-By", "Via", "Set-Cookie":
		return true
	}
	return strings.HasPrefix(n, "X-") && !notIdentity[n]
}

// WithoutIdentity is h without the headers that name software, for a reader
// that asks what the rest of an answer says on its own.
func WithoutIdentity(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		if !IdentityHeader(k) {
			out[k] = v
		}
	}
	return out
}

// proxyRead is what the run learned about the -proxy's own answer, and what
// it dropped from the targets' answers by it.
type proxyRead struct {
	mu      sync.Mutex
	asked   bool
	host    string
	socks   bool        // a SOCKS5 proxy relays bytes: it has no HTTP answer to ask for
	failed  string      // why it could not be asked, "" when it was
	own     http.Header // the identity headers of its own answer
	answers int         // target answers that came through it
	dropped map[string]*droppedHeader
}

type droppedHeader struct {
	answers int
	value   string
}

func (r *proxyRead) reset() {
	r.mu.Lock()
	r.asked, r.host, r.socks, r.failed, r.own, r.answers, r.dropped = false, "", false, "", nil, 0, nil
	r.mu.Unlock()
}

// viaTargetProxy is -proxy when req goes through it, nil otherwise.
func (g *guarded) viaTargetProxy(req *http.Request) *url.URL {
	if g.class != Target || g.base == nil || g.base.Proxy == nil {
		return nil
	}
	tp := Current().TargetProxy()
	if tp == nil {
		return nil
	}
	if u, err := g.base.Proxy(req); err != nil || u == nil || u.String() != tp.String() {
		return nil
	}
	return tp
}

// learnProxy asks pu for its own answer, once per run.
func (p *Policy) learnProxy(ctx context.Context, pu *url.URL) {
	r := &p.px
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.asked {
		return
	}
	if pu.Scheme == "socks5" || pu.Scheme == "socks5h" {
		r.asked, r.socks, r.host = true, true, pu.Host
		return
	}
	h, err := askProxy(ctx, pu)
	if errors.Is(err, neterr.ErrKilled) {
		return // the run is stopping: ask again if it goes on
	}
	r.asked, r.host = true, pu.Host
	if err != nil {
		r.failed = err.Error()
		return
	}
	r.own = h
}

// askProxy sends the proxy a request addressed to the proxy itself, not
// through it, and returns the identity headers of its answer. The request is
// the user's own proxy's, recorded in the ledger apart from the targets'.
func askProxy(ctx context.Context, pu *url.URL) (http.Header, error) {
	if err := Current().Killed(); err != nil {
		return nil, err
	}
	tr := &http.Transport{
		DialContext:           DialProxy,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, // a proxy such as Burp signs its own
	}
	c := &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &guarded{class: Proxy, base: tr, rt: wrapLedger(Proxy, tr)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer tr.CloseIdleConnections()
	ctx = ledger.WithCollector(context.WithoutCancel(ctx), "proxy")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, (&url.URL{Scheme: pu.Scheme, Host: pu.Host, Path: "/"}).String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "azhaq")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	own := http.Header{}
	for k, v := range resp.Header {
		if IdentityHeader(k) {
			own[k] = slices.Clone(v)
		}
	}
	return own, nil
}

// dropProxyOwn removes from h every value the proxy's own answer showed, and
// counts the answer.
func (p *Policy) dropProxyOwn(h http.Header) {
	r := &p.px
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.asked || r.socks {
		return
	}
	r.answers++
	for name, ownVals := range r.own {
		vs, ok := h[name]
		if !ok {
			continue
		}
		kept := vs[:0:0]
		for _, v := range vs {
			if !slices.Contains(ownVals, v) {
				kept = append(kept, v)
			}
		}
		if len(kept) == len(vs) {
			continue
		}
		if r.dropped == nil {
			r.dropped = map[string]*droppedHeader{}
		}
		d := r.dropped[name]
		if d == nil {
			d = &droppedHeader{value: strings.Join(slices.DeleteFunc(slices.Clone(vs), func(v string) bool { return !slices.Contains(ownVals, v) }), ", ")}
			r.dropped[name] = d
		}
		d.answers++
		if len(kept) == 0 {
			delete(h, name)
		} else {
			h[name] = kept
		}
	}
}

// DropProxyOwn is h, the headers of an answer to a target read some way other
// than through a client of egress (Chrome's), without what the -proxy's own
// answer showed.
func DropProxyOwn(h http.Header) { Current().dropProxyOwn(h) }

// ProxyUnasked says the run goes through an HTTP proxy that could not be asked
// for its own answer: what a header alone says of a target may be the proxy's.
func ProxyUnasked() bool {
	r := &Current().px
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.asked && r.failed != ""
}

// ProxyNotes are the lines about -proxy's headers for the run's notes.
func ProxyNotes() []string {
	r := &Current().px
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	switch {
	case !r.asked:
		return nil
	case r.socks:
		return []string{fmt.Sprintf("-proxy %s is a SOCKS5 proxy: it relays the connection and sends no HTTP answer of its own, so it was not asked for one", r.host)}
	case r.failed != "":
		return []string{fmt.Sprintf("-proxy %s could not be asked for its own answer (%s): a product or version that only a header of an answer gave is marked as read through the proxy, and no advisory is matched to such a version", r.host, r.failed)}
	}
	names := make([]string, 0, len(r.dropped))
	for n := range r.dropped {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d := r.dropped[n]
		out = append(out, fmt.Sprintf("-proxy %s: %d of %d answers carried a %s header equal to the proxy's own (%q); it is not read as the target's, so no product, version or advisory comes from it", r.host, d.answers, r.answers, n, d.value))
	}
	return out
}
