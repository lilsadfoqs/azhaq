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
//
// A request sent to a proxy can reach the target (a proxy that forwards every
// request does so for this one too), so the ask counts like a target's: it
// spends from -max-requests, waits for the pace, and is in the summary's
// requests and the ledger.

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
	keep    bool   // the commands of one run share the ask (ShareProxyAsk)
	sent    int    // asks sent by the run, or the command that shares it: the summary names them
	proxy   string // the proxy asked, to know it again
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
	r.answers, r.dropped = 0, nil
	if !r.keep {
		r.forget()
	}
	r.mu.Unlock()
}

// setProxy starts the counts over for the proxy u. What was learned is kept
// for the same proxy while the ask is shared.
func (r *proxyRead) setProxy(u *url.URL) {
	r.mu.Lock()
	r.answers, r.dropped = 0, nil
	if !r.keep || u == nil || u.String() != r.proxy {
		r.forget()
	}
	r.mu.Unlock()
}

func (r *proxyRead) forget() {
	r.asked, r.sent, r.proxy, r.host, r.socks, r.failed, r.own = false, 0, "", "", false, "", nil
}

// ShareProxyAsk makes a command that runs others in turn (roles, the live
// check of urls) ask the -proxy once for all of them: a reset between its
// runs keeps what the ask learned. Off ends it and forgets.
func ShareProxyAsk(on bool) {
	r := &Current().px
	r.mu.Lock()
	r.keep = on
	if !on {
		r.forget()
	}
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

// learnProxy asks pu for its own answer, once per run. The ask is a request
// the proxy may forward, so it is counted and paced as a target's: with the
// budget spent it is not sent, and the proxy counts as one that could not be
// asked. The caller's own request was counted and paced already, so the ask
// takes its place in the pace and the caller waits for another. An error
// means the run is stopping: the caller's request is not sent either.
func (p *Policy) learnProxy(ctx context.Context, pu *url.URL) error {
	r := &p.px
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.asked {
		return nil
	}
	if pu.Scheme == "socks5" || pu.Scheme == "socks5h" {
		r.asked, r.socks, r.host, r.proxy = true, true, pu.Host, pu.String()
		return nil
	}
	if err := p.spendAsk(ctx); err != nil {
		if !errors.Is(err, neterr.ErrBudget) {
			return err // the run is stopping: ask again if it goes on
		}
		r.asked, r.host, r.proxy = true, pu.Host, pu.String()
		r.failed = "the -max-requests budget was spent before it could be asked"
		return nil
	}
	h, err := askProxy(ctx, pu)
	if errors.Is(err, neterr.ErrKilled) {
		return err // admit gave the request back
	}
	r.asked, r.host, r.proxy = true, pu.Host, pu.String()
	if err != nil {
		r.failed = err.Error()
		if ledger.NotReached(err) {
			return nil // nothing left, so nothing was sent or counted
		}
	} else {
		r.own = h
	}
	r.sent++
	return p.Pace(ctx)
}

// spendAsk counts the ask of the -proxy as a request to a target. A refusal
// marks no task as capped: the request the ask comes with was sent.
func (p *Policy) spendAsk(ctx context.Context) error {
	if err := p.Killed(); err != nil {
		return err
	}
	for {
		n := p.sent.Load()
		if m := p.maxReq.Load(); m > 0 && n >= m {
			return neterr.ErrBudget
		}
		if p.sent.CompareAndSwap(n, n+1) {
			break
		}
	}
	p.useReserve()
	if w, _ := ctx.Value(refusedKey{}).(*watch); w != nil {
		w.used.Add(1)
	}
	return nil
}

// askProxy sends the proxy a request addressed to the proxy itself, not
// through it, and returns the identity headers of its answer. The request is
// the user's own proxy's, recorded in the ledger apart from the targets'.
func askProxy(ctx context.Context, pu *url.URL) (http.Header, error) {
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
		Refund() // never sent
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

// ProxyAskNote names the ask the run sent to its -proxy, "" when it sent none.
func ProxyAskNote() string {
	r := &Current().px
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sent == 0 {
		return ""
	}
	return fmt.Sprintf("1 request to the -proxy itself (%s), for its own answer: counted in requests and in -max-requests and paced like a target's, because a proxy that forwards every request passes it on to the target", r.host)
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
