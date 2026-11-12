package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/scope"
)

// guarded is the transport of every client egress hands out. Before a
// request goes it applies the controls of its class, then the ledger
// records it (and holds back what -deny-path or a killed run's writes say).
type guarded struct {
	class Class
	base  *http.Transport
	sni   string // the server name every handshake asks for, "" for the URL's host
	rt    http.RoundTripper
	leg   legacyHTTP
}

// wrapLedger records rt's requests as class's, and keeps them off
// connections the other end has closed.
func wrapLedger(class Class, rt http.RoundTripper) http.RoundTripper {
	out := ledger.WrapAs(string(class), rt)
	if t, ok := out.(*ledger.Transport); ok && t.Dead == nil {
		t.Dead = connDead
	}
	return out
}

func newGuarded(class Class, base *http.Transport, sni string) *guarded {
	g := &guarded{class: class, base: base, sni: sni}
	if class == Own || class == DNS {
		g.rt = base // the user's own, or a DNS query the exchanger records itself
	} else {
		g.rt = wrapLedger(class, base)
	}
	return g
}

func (g *guarded) RoundTrip(req *http.Request) (*http.Response, error) {
	own := g.class == Target && !isExclusive(req.Context())
	if own {
		wire.RLock() // a measurement without the session waits for this one
		defer wire.RUnlock()
	}
	if err := g.admit(req); err != nil {
		return nil, err
	}
	out := keepTargetInRequestLine(g.base, req)
	resp, err := g.send(out)
	err = g.nameProxy(req, err)
	if resp != nil && out != req {
		resp.Request = req
	}
	if resp != nil && own && SessionWire != nil && !isUnwatched(req.Context()) {
		SessionWire(req, resp)
	}
	return resp, err
}

// nameProxy says which proxy a request that could not reach it went to:
// "proxy 127.0.0.1:1: connection refused", not the target's refusal.
func (g *guarded) nameProxy(req *http.Request, err error) error {
	if err == nil || !ledger.ProxyDown(err) {
		return err
	}
	var oe *net.OpError
	errors.As(err, &oe)
	host := ""
	if g.base != nil && g.base.Proxy != nil {
		if u, perr := g.base.Proxy(req); perr == nil && u != nil {
			host = u.Host
		}
	}
	if host == "" {
		host = "(the -proxy)"
	}
	return &neterr.ProxyUnreachable{Proxy: host, Err: oe.Err}
}

// keepTargetInRequestLine is req, changed when it goes to an HTTP proxy in
// absolute form: Go writes that request line with the Host header's authority,
// so a Host that differs from the URL's would send the proxy to another host
// or port. The request line then names the URL's authority and the Host header
// stays as set. A -raw path (Opaque) loses its absolute form the same way.
func keepTargetInRequestLine(base *http.Transport, req *http.Request) *http.Request {
	u := req.URL
	if base == nil || base.Proxy == nil || u == nil || u.Scheme != "http" || u.Host == "" {
		return req
	}
	opaque := u.Opaque
	switch {
	case opaque == "":
		if req.Host == "" || strings.EqualFold(req.Host, u.Host) {
			return req
		}
		opaque = u.EscapedPath()
		if opaque == "" {
			opaque = "/"
		}
	case strings.HasPrefix(opaque, "//") || !strings.HasPrefix(opaque, "/"):
		return req
	}
	if p, err := base.Proxy(req); err != nil || p == nil || (p.Scheme != "http" && p.Scheme != "https") {
		return req
	}
	out := *req
	cu := *u
	cu.Opaque = "//" + u.Host + opaque
	out.URL = &cu
	return &out
}

// admit holds req to the checks of its class and closes its body when it
// is refused. A request to a target is counted by its sender, except a
// redirect hop the client follows (req.Response is the answer that sent
// it): nobody counted that, so it is counted and paced here, and the
// budget can refuse it.
func (g *guarded) admit(req *http.Request) error {
	hop := g.class == Target && req.Response != nil
	err := g.check(req)
	if err == nil && hop {
		// Counted and paced, not checked against the session: the request
		// the hop belongs to was, and a hop that waited on a session check
		// would hold the wire (see Exclusive) while the check waits for it.
		err = Current().SpendCounted(req.Context(), true)
	} else if err != nil && g.class == Target && !hop {
		Refund() // counted by its sender, never sent
	}
	if err != nil && req.Body != nil {
		req.Body.Close()
	}
	return err
}

// check is what a request is held to before it leaves: the kill file
// for every class but the user's own, and for a target the scope, which
// covers the URL's host, the Host header, every header that names a host
// and the server name the handshake asks for.
func (g *guarded) check(req *http.Request) error {
	if g.class == Own {
		return nil
	}
	p := Current()
	if err := p.Killed(); err != nil {
		return err
	}
	if g.class != Target {
		return nil
	}
	if err := admitGuess(req); err != nil {
		return err
	}
	return p.checkRequest(req, g.sni)
}

// checkRequest refuses a request a front end could route to a host outside
// the scope: neterr.ErrOutOfScope. Without a scope it holds nothing back.
func (p *Policy) checkRequest(req *http.Request, sni string) error {
	allow, open := p.scope()
	if req.URL == nil {
		return nil
	}
	if h := req.URL.Hostname(); h != "" && (allow != nil || p.heldByTargets(h, scope.URLPort(req.URL))) {
		if err := p.CheckAddr(h, scope.URLPort(req.URL)); err != nil {
			return err
		}
	}
	if allow == nil {
		return nil
	}
	addr := p.ScopeAddr()
	if req.Host != "" && !open["host"] {
		if h, port := hostPortOf(req.Host); h != "" && !addr(h, port) {
			return p.outOf(h)
		}
	}
	for name, vs := range req.Header {
		if open[strings.ToLower(name)] {
			continue
		}
		for _, v := range vs {
			if h := scope.HeaderOutsideBy(addr, name, v); h != "" {
				return p.outOf(h)
			}
		}
	}
	if sni != "" && !open["sni"] && !allow(sni) {
		return neterr.ErrOutOfScope
	}
	return nil
}

// outOf is why a host a header names is refused: its port when the host is in
// scope on another, else the scope.
func (p *Policy) outOf(host string) error {
	if p.Allows(host) {
		if p.namedByTargets(host) {
			return neterr.ErrOutOfTargetPort
		}
		return neterr.ErrOutOfPort
	}
	return neterr.ErrOutOfScope
}

// hostPortOf splits a Host header's value; the port is "" when it names none.
func hostPortOf(hostport string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(hostport, "[]"), ""
}

// CloseIdleConnections passes on to the transport, as http.Client looks for it.
func (g *guarded) CloseIdleConnections() {
	g.base.CloseIdleConnections()
	g.leg.closeIdle()
}

// ProxyOf is the proxy a request through c would go through, nil for none:
// -proxy's for a client egress made for targets, the environment's for one
// without a transport.
func ProxyOf(c *http.Client, req *http.Request) (*url.URL, error) {
	var tr http.RoundTripper
	if c != nil {
		tr = c.Transport
	}
	switch t := Unwrap(tr).(type) {
	case *http.Transport:
		if t.Proxy == nil {
			return nil, nil
		}
		return t.Proxy(req)
	case nil:
		return http.ProxyFromEnvironment(req)
	}
	return nil, nil
}

// Unwrap is the *http.Transport under a client's transport that egress
// made, or rt itself.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if g, ok := rt.(*guarded); ok {
		return g.base
	}
	return ledger.Unwrap(rt)
}

// TargetOptions are what a client to targets can be set apart by. Zero
// values are the defaults.
type TargetOptions struct {
	// Timeout is the whole request, HeaderTimeout the wait for the first
	// byte of the answer, HandshakeTimeout the TLS handshake.
	Timeout, HeaderTimeout, HandshakeTimeout time.Duration
	// TLS is the handshake's settings; nil takes any certificate, TLS 1.2 up.
	// Its ServerName is held to the scope like a Host header.
	TLS *tls.Config
	// NoReuse opens a connection for every request.
	NoReuse bool
	// Proxy replaces -proxy (and the environment's) for this client.
	Proxy *url.URL
	// Follow lets the client follow redirects; by default it answers with
	// the redirect itself.
	Follow bool
}

// TargetClient is an HTTP client for requests to targets: the guard checks
// each against the scope and the kill file, the ledger records it, a name
// connects through the run's resolver, and the request goes through -proxy.
// It sends no more than what its caller counts with Spend.
func TargetClient(o TargetOptions) *http.Client {
	cfg := o.TLS
	if cfg == nil {
		cfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	proxy := ProxyFor
	if o.Proxy != nil {
		proxy = http.ProxyURL(o.Proxy)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		DialContext:           dialThrough,
		DisableKeepAlives:     o.NoReuse,
		TLSHandshakeTimeout:   o.HandshakeTimeout,
		ResponseHeaderTimeout: o.HeaderTimeout,
		TLSClientConfig:       cfg,
	}
	c := &http.Client{Timeout: o.Timeout, Transport: newGuarded(Target, tr, cfg.ServerName)}
	if !o.Follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// TargetFrom is c, a client someone else made (a test's server client, one
// the run was given), with its requests held to the target controls: c
// itself when it already is.
func TargetFrom(c *http.Client) *http.Client { return from(Target, c) }

// from is c with its transport held to the controls of class. Its transport
// is kept: an *http.Transport is guarded, any other RoundTripper is wrapped.
func from(class Class, c *http.Client) *http.Client {
	if g, ok := c.Transport.(*guarded); ok && g.class == class {
		return c
	}
	cp := *c
	switch t := Unwrap(c.Transport).(type) {
	case *http.Transport:
		cp.Transport = newGuarded(class, t, "")
	case nil:
		cp.Transport = newGuarded(class, http.DefaultTransport.(*http.Transport), "")
	default:
		cp.Transport = &foreign{rt: wrapLedger(class, t), g: newGuarded(class, &http.Transport{}, "")}
	}
	return &cp
}

// foreign holds a transport that is not an *http.Transport to the same
// checks and records.
type foreign struct {
	rt http.RoundTripper
	g  *guarded
}

func (f *foreign) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := f.g.admit(req); err != nil {
		return nil, err
	}
	return f.rt.RoundTrip(req)
}

// Tweak is c with its transport copied and changed by f: timeouts, TLS
// settings, connection limits. The copy is held to the same controls; f
// does not decide where a connection goes. c is returned as it is when it
// was not made by egress.
func Tweak(c *http.Client, f func(*http.Transport)) *http.Client {
	g, ok := c.Transport.(*guarded)
	if !ok {
		return c
	}
	t := g.base.Clone()
	f(t)
	cp := *c
	sni := g.sni
	if t.TLSClientConfig != nil {
		sni = t.TLSClientConfig.ServerName
	}
	cp.Transport = newGuarded(g.class, t, sni)
	return &cp
}

// Pinned is c with every connection going to ip, not to a pooled one for
// the name; the request is still the URL's (its Host, its scope).
func Pinned(c *http.Client, ip string) *http.Client {
	return Tweak(c, func(t *http.Transport) {
		t.DisableKeepAlives = true
		t.DialContext = pinnedDial(ip)
	})
}

// SourceOptions are what a client to a third-party source can be set apart by.
type SourceOptions struct {
	Timeout time.Duration
	// Proxy sends the requests through this URL; nil takes the environment's
	// (HTTP_PROXY, HTTPS_PROXY), as the default transport does.
	Proxy *url.URL
}

// SourceClient is an HTTP client for a third party the run asks about its
// targets (archives, RDAP, search engines, a scope platform, a notification
// service): not held to the target scope, held to the kill file, sent
// through the proxy given for it, verified by the system's certificates, and
// recorded in the ledger as a source.
func SourceClient(o SourceOptions) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if o.Proxy != nil {
		tr.Proxy = http.ProxyURL(o.Proxy)
	}
	return &http.Client{Timeout: o.Timeout, Transport: newGuarded(Source, tr, "")}
}

// SourceFrom is c, a client someone else made, with its requests held to
// the source controls and recorded as a source's; c itself when it
// already is.
func SourceFrom(c *http.Client) *http.Client { return from(Source, c) }

// OwnOptions are what a client to the user's own endpoint can be set apart by.
type OwnOptions struct {
	Timeout time.Duration
	// Proxy sends the requests through this URL; nil: the environment's.
	Proxy *url.URL
	// Insecure takes any certificate: a proxy such as Burp signs its own.
	// TLS, when set, is used as it is instead.
	Insecure bool
	TLS      *tls.Config
	// Follow lets the client follow redirects.
	Follow bool
}

// OwnClient is an HTTP client for an endpoint of the user's own: a replay
// proxy, a worker's link to its run, where -seal-to posts the seal. Nothing
// is held back and nothing is recorded: it is not a request about a target.
func OwnClient(o OwnOptions) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	switch {
	case o.TLS != nil:
		tr.TLSClientConfig = o.TLS
	case o.Insecure:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	}
	if o.Proxy != nil {
		tr.Proxy = http.ProxyURL(o.Proxy)
	}
	c := &http.Client{Timeout: o.Timeout, Transport: newGuarded(Own, tr, "")}
	if !o.Follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// H2Client is a client that speaks HTTP/2 over TLS to a target, taking any
// certificate, for the probe that asks whether a server does. Its requests
// are held and recorded like TargetClient's.
func H2Client(timeout time.Duration) *http.Client {
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := dialThrough(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			cfg = cfg.Clone()
			cfg.InsecureSkipVerify, cfg.ServerName = true, host
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	return &http.Client{Timeout: timeout, Transport: &foreign{rt: wrapLedger(Target, tr), g: newGuarded(Target, &http.Transport{}, "")}}
}

// CloseIdleConnections passes on to the transport under it.
func (f *foreign) CloseIdleConnections() {
	if c, ok := f.rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
