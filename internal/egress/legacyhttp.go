package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
)

// legacyHTTP is what a client of targets keeps for the servers crypto/tls
// cannot handshake with (see legacytls.go): a second transport that dials
// with the fallback client, and the addresses that needed it, so a host that
// did is not first asked with crypto/tls on every request.
type legacyHTTP struct {
	once  sync.Once
	tr    atomic.Pointer[http.Transport]
	rec   http.RoundTripper // tr with its requests recorded, for a host already known
	hosts sync.Map          // host:port → struct{}
}

// send is g.rt.RoundTrip for a request to an https URL of a target with the
// fallback behind it: when crypto/tls fails the handshake (and only then: no
// byte of the request was written) with an error LegacyTLSNeeded names, the
// same request goes again on a connection of the fallback client. The ledger
// has it once, as the first try recorded it; a host the fallback served is
// asked with it from then on, recorded by its own transport.
func (g *guarded) send(req *http.Request) (*http.Response, error) {
	if g.class != Target || req.URL == nil || req.URL.Scheme != "https" || g.base.TLSClientConfig == nil || !g.base.TLSClientConfig.InsecureSkipVerify {
		return g.rt.RoundTrip(req)
	}
	key := hostPortKey(req.URL)
	if _, known := g.leg.hosts.Load(key); known {
		return g.legacyRoundTrip(req, key, true)
	}
	var shake handshakeWatch
	first := req.WithContext(httptrace.WithClientTrace(req.Context(), shake.trace()))
	resp, err := g.rt.RoundTrip(first)
	if err == nil || !LegacyTLSNeeded(shake.get()) || req.Context().Err() != nil {
		return resp, err
	}
	retry := req
	if req.Body != nil && req.Body != http.NoBody { // the first try closed it
		if req.GetBody == nil {
			return resp, err
		}
		body, berr := req.GetBody()
		if berr != nil {
			return resp, err
		}
		retry = req.Clone(req.Context())
		retry.Body = body
	}
	resp, lerr := g.legacyRoundTrip(retry, key, false)
	if lerr != nil {
		return nil, fmt.Errorf("%w; fallback TLS client: %v", err, lerr)
	}
	resp.Request = req
	return resp, nil
}

// handshakeWatch notes how the TLS handshake of a request ended.
type handshakeWatch struct {
	mu  sync.Mutex
	err error
}

func (h *handshakeWatch) get() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

func (h *handshakeWatch) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
		h.mu.Lock()
		h.err = err
		h.mu.Unlock()
	}}
}

// legacyRoundTrip sends req on the fallback transport, through the proxy a
// request of this client would use. record puts the request in the ledger.
func (g *guarded) legacyRoundTrip(req *http.Request, key string, record bool) (*http.Response, error) {
	g.leg.once.Do(func() {
		t := g.base.Clone()
		t.Proxy = nil // the dial goes through it: crypto/tls would run the handshake over the tunnel
		t.DialTLSContext = g.legacyDial
		g.leg.tr.Store(t)
		g.leg.rec = wrapLedger(g.class, t)
	})
	ctx := req.Context()
	if g.base.Proxy != nil {
		if pu, err := g.base.Proxy(req); err == nil && pu != nil {
			ctx = context.WithValue(ctx, legacyProxyKey{}, pu)
		}
	}
	var lc *legacyConn
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		lc, _ = info.Conn.(*legacyConn)
	}})
	rt := http.RoundTripper(g.leg.tr.Load())
	if record {
		rt = g.leg.rec
	}
	resp, err := rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if lc != nil {
		st := lc.ConnectionState()
		resp.TLS = &st
	}
	g.leg.hosts.Store(key, struct{}{})
	return resp, nil
}

// legacyDial is the fallback transport's dial: a connection through the run's
// resolver (or the proxy), and the handshake of the fallback client on it.
func (g *guarded) legacyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var conn net.Conn
	var err error
	if pu, _ := ctx.Value(legacyProxyKey{}).(*url.URL); pu != nil {
		conn, err = dialVia(ctx, pu, addr)
	} else {
		conn, err = dialThrough(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	if t := g.base.TLSHandshakeTimeout; t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	host, _, _ := net.SplitHostPort(addr)
	lc, err := legacyClient(ctx, conn, g.base.TLSClientConfig, host)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return lc, nil
}

func (l *legacyHTTP) closeIdle() {
	if t := l.tr.Load(); t != nil {
		t.CloseIdleConnections()
	}
}

// hostPortKey is the host and port a URL's connection goes to.
func hostPortKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}
