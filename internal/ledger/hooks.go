package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

type collectorKey struct{}

// WithCollector marks ctx with the collector whose work it is, for the
// entries made with it.
func WithCollector(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, collectorKey{}, name)
}

type opaqueKey struct{}

// WithOpaqueTarget marks ctx so that the requests made with it are
// recorded by their scheme and host only, never their path, query or user:
// a webhook's URL is a secret.
func WithOpaqueTarget(ctx context.Context) context.Context {
	return context.WithValue(ctx, opaqueKey{}, true)
}

func opaque(ctx context.Context) bool {
	ok, _ := ctx.Value(opaqueKey{}).(bool)
	return ok
}

// CollectorOf is the collector whose work ctx is (see WithCollector), or "".
func CollectorOf(ctx context.Context) string { return collectorOf(ctx) }

func collectorOf(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(collectorKey{}).(string)
	return s
}

var sentByClass [4]atomic.Int64

func counter(class string) *atomic.Int64 {
	switch class {
	case ClassSource:
		return &sentByClass[1]
	case ClassDNS:
		return &sentByClass[2]
	case ClassOwn:
		return &sentByClass[3]
	}
	return &sentByClass[0]
}

// Sent is how many requests and connections of class (ClassSource, ...) the
// process has handed to the ledger's hooks, recorded or not: what a summary
// says about them is what the ledger would list.
func Sent(class string) int64 { return counter(class).Load() }

// HTTP records req, about to be sent to a target. It is a no-op without a
// ledger.
func HTTP(req *http.Request) { HTTPAs(ClassTarget, req) }

// HTTPAs is HTTP for a request of another class.
func HTTPAs(class string, req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	counter(class).Add(1)
	purpose := purposeFor(req.Context(), "http", collectorOf(req.Context()), req.URL)
	spend(class, "http", collectorOf(req.Context()), purpose, 1)
	if f := OnSent; f != nil && class == ClassTarget {
		f(req.Method, req.URL.String())
	}
	l := Active()
	if l == nil {
		return
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	host := req.URL.Hostname()
	vhost := req.Host
	if vhost == req.URL.Host || vhost == host {
		vhost = ""
	}
	target := req.URL.Redacted()
	if opaque(req.Context()) {
		target = req.URL.Scheme + "://" + req.URL.Host + "/…"
	}
	e := Entry{Kind: "http", Class: class, Method: method, Target: target, Host: host, VHost: vhost,
		Body: bodySum(req), Collector: collectorOf(req.Context())}
	if class == ClassTarget {
		e.Rule, e.Purpose = l.rule(host), purpose
	}
	l.Record(e)
}

// bodySum is the start of the sha256 of req's body, "" for none; it reads
// a copy (GetBody), never the body being sent.
func bodySum(req *http.Request) string {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Deny, when set, is asked about each request before it is sent: an error
// holds it back (a -deny-path rule). Every client of the run sends through
// Transport, so no collector steps round the rule.
var Deny func(raw string) error

// Hold, when set, is asked about each GET or HEAD before it is sent, after
// Deny: an error holds it back (a GET found on the way whose own name
// declares a state change). The request's context says who asked for it.
var Hold func(req *http.Request) error

// OnSent, when set, hears of each request to a target as it is recorded
// (the same moment the ledger line is made, with or without a ledger file):
// what a summary calls sent is what this heard.
var OnSent func(method, raw string)

// Unsent is called for a request Transport held back after it was counted
// (fetch gives it back to the budget).
var Unsent func()

// NotSent records a request that failed before any byte of it left: its
// transport could not reach the -proxy. It is not counted as sent (no
// tally, no spend, no OnSent); the line says it was tried.
func NotSent(class string, req *http.Request) {
	l := Active()
	if l == nil || req == nil || req.URL == nil {
		return
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	host := req.URL.Hostname()
	target := req.URL.Redacted()
	if opaque(req.Context()) {
		target = req.URL.Scheme + "://" + req.URL.Host + "/…"
	}
	e := Entry{Kind: "http", Class: class, Method: method, Target: target, Host: host, Collector: collectorOf(req.Context()), NotSent: true}
	if class == ClassTarget {
		e.Rule = l.rule(host)
	}
	l.Record(e)
}

// ProxyDown says err is a failure to reach the proxy a request was to go
// through: nothing of the request left.
func ProxyDown(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "proxyconnect"
}

// Chrome records a request Chrome sent. ctx may be nil.
func Chrome(ctx context.Context, method, raw string) { ChromeAt(ctx, method, raw, time.Time{}) }

// ChromeAt is Chrome for a request sent at a time already past; zero is now.
func ChromeAt(ctx context.Context, method, raw string, at time.Time) {
	purpose := purposeFor(ctx, "chrome", collectorOf(ctx), nil)
	spend(ClassTarget, "chrome", collectorOf(ctx), purpose, 1)
	if f := OnSent; f != nil {
		f(method, raw)
	}
	l := Active()
	if l == nil {
		return
	}
	var host string
	if u, err := url.Parse(raw); err == nil {
		host = u.Hostname()
		raw = u.Redacted()
	}
	if method == "" {
		method = http.MethodGet
	}
	l.Record(Entry{Time: at, Kind: "chrome", Class: ClassTarget, Method: method, Target: raw, Host: host,
		Rule: l.rule(host), Collector: collectorOf(ctx), Purpose: purpose})
}

// TCP records a connection about to be made to a target at addr (ip:port).
// host is the name it was found under, "" when only the address is known.
func TCP(ctx context.Context, host, addr string) { TCPAs(ctx, ClassTarget, host, addr) }

// TCPAs is TCP for a connection of another class.
func TCPAs(ctx context.Context, class, host, addr string) {
	counter(class).Add(1)
	spend(class, "tcp", collectorOf(ctx), purposeFor(ctx, "tcp", "", nil), 1)
	l := Active()
	if l == nil {
		return
	}
	l.Record(tcpEntry(l, ctx, class, host, addr))
}

// tcpEntry is the line of a connection to addr.
func tcpEntry(l *Ledger, ctx context.Context, class, host, addr string) Entry {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	name := host
	if name == "" {
		name = ip
	}
	var rule, purpose string
	if class == ClassTarget {
		purpose = purposeFor(ctx, "tcp", "", nil)
		if rule = l.rule(name); rule == "" && name != ip {
			rule = l.rule(ip)
		}
	}
	return Entry{Kind: "tcp", Class: class, Target: addr, Host: host, Rule: rule, Collector: collectorOf(ctx), Purpose: purpose}
}

// TCPBatch records connections about to be made to the targets at addrs
// (ip:port), in one write: each is a line before its connect goes.
func TCPBatch(ctx context.Context, host string, addrs []string) {
	counter(ClassTarget).Add(int64(len(addrs)))
	spend(ClassTarget, "tcp", collectorOf(ctx), purposeFor(ctx, "tcp", "", nil), int64(len(addrs)))
	l := Active()
	if l == nil || len(addrs) == 0 {
		return
	}
	es := make([]Entry, 0, len(addrs))
	for _, addr := range addrs {
		es = append(es, tcpEntry(l, ctx, ClassTarget, host, addr))
	}
	l.RecordMany(es)
}

// DNS records a query about to be sent to a resolver: the name, its type
// ("A") and the resolver's address or URL.
func DNS(ctx context.Context, name, qtype, server string) {
	spend(ClassDNS, "dns", collectorOf(ctx), "", 1)
	l := Active()
	if l == nil {
		return
	}
	l.Record(Entry{Kind: "dns", Class: ClassDNS, Method: qtype, Target: server, Host: name, Rule: l.rule(name), Collector: collectorOf(ctx)})
}

// Transport records each request once it has been written to its
// connection (or the write failed with no stop to blame), so a request a stop
// cancelled before it left is not listed: it is given back to the budget (Unsent) instead. One that went
// out and failed still appears, and so does one whose connection attempt
// failed or whose TLS handshake began, or that failed with no stop to blame
// (no address for the name, a connection dropped before the write): those were
// tried though no request was written. Class is what the
// requests are sent to (ClassTarget when empty); only a target's are held
// by -deny-path and by the writes a killed run sent.
type Transport struct {
	Base  http.RoundTripper
	Class string
	// Dead, when set, says a pooled connection was closed by its other end:
	// the request is not written to it, and is not recorded for it. The
	// transport takes another connection.
	Dead func(net.Conn) bool

	freshOnce sync.Once
	freshRT   http.RoundTripper
}

// leaving settles, for one request, whether it left: the first of the
// events that say so records it, and what comes after the call returned
// does not.
type leaving struct {
	mu       sync.Mutex
	recorded bool
	done     bool
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	class := t.Class
	if class == "" {
		class = ClassTarget
	}
	if f := Deny; f != nil && req.URL != nil && class == ClassTarget {
		if err := f(req.URL.String()); err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			if Unsent != nil {
				Unsent()
			}
			return nil, err
		}
	}
	if f := Hold; f != nil && req.URL != nil && class == ClassTarget {
		if err := f(req); err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			if Unsent != nil {
				Unsent()
			}
			return nil, err
		}
	}
	if l := Active(); l != nil && class == ClassTarget && req.URL != nil && !Safe(req.Method) && l.refused(req.Method, req.URL.Redacted(), bodySum(req), false) {
		if req.Body != nil {
			req.Body.Close()
		}
		if Unsent != nil {
			Unsent()
		}
		return nil, neterr.ErrNotRepeated
	}
	var lv leaving
	record := func() {
		lv.mu.Lock()
		defer lv.mu.Unlock()
		if !lv.recorded && !lv.done {
			lv.recorded = true
			HTTPAs(class, req)
		}
	}
	// finish ends the call: a request nothing says left is given back.
	finish := func() {
		lv.mu.Lock()
		defer lv.mu.Unlock()
		lv.done = true
		if !lv.recorded && class == ClassTarget && Unsent != nil {
			Unsent()
		}
	}
	for try := 0; ; try++ {
		var reused, skipped, answered, reached atomic.Bool
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				reused.Store(info.Reused)
				if info.Reused && t.Dead != nil && info.Conn != nil && t.Dead(info.Conn) {
					// Closed under the pool: nothing is written to it.
					skipped.Store(true)
					info.Conn.Close()
				}
			},
			ConnectDone: func(_, _ string, err error) {
				if err != nil {
					reached.Store(true) // a SYN left and nothing answered it
				}
			},
			TLSHandshakeStart: func() { reached.Store(true) }, // a ClientHello leaves
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				// The write was made. One that failed because the other end reset the
				// connection was still tried; one that failed because a stop closed
				// the connection may have left nothing at all.
				if (info.Err == nil || req.Context().Err() == nil) && !skipped.Load() {
					record() // the first live connection: later ones are a replay of it
				}
			},
			GotFirstResponseByte: func() { answered.Store(true) },
		}
		ctx := req.Context()
		if try > 0 {
			ctx = context.WithValue(ctx, replayKey{}, true)
		}
		sent := req.WithContext(httptrace.WithClientTrace(ctx, trace))
		if try > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				finish()
				return nil, err
			}
			sent.Body = body
		}
		rt := t.base()
		if try > 0 {
			rt = t.fresh()
		}
		resp, err := rt.RoundTrip(sent)
		// A pooled connection the server closed and nobody saw close: the request
		// went nowhere (the transport replays only a read, and fails a write it
		// cannot tell from one that was answered). It is made again, on another
		// connection, and is one request: the server read it once, the ledger and
		// the count hold it once. The transport's own retry of it may have met the
		// kill file at its dial: the request was listed when it was written, so it
		// is made again too.
		if err != nil && try < maxReplays && reused.Load() && (skipped.Load() || !answered.Load() && (closedByPeer(err) || errors.Is(err, neterr.ErrKilled))) && req.Context().Err() == nil &&
			(req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
			continue
		}
		// It was answered (the write's report may come late), or it was tried: a
		// connect failed, a handshake began, or it failed for a reason no stop is
		// to blame for (a name with no address, a connection the other end dropped
		// before the write). Only a request a stop cancelled, or the kill file
		// refused, before it left is not listed.
		switch {
		case resp == nil && ProxyDown(err) && req.Context().Err() == nil:
			// The proxy was not reached: no byte of the request left, so it is
			// listed as tried and counted by nobody (finish gives it back).
			lv.mu.Lock()
			if !lv.recorded {
				lv.done = true // no later event may count it
				NotSent(class, req)
			}
			lv.mu.Unlock()
		case resp != nil || (err != nil && (reached.Load() || req.Context().Err() == nil && !errors.Is(err, neterr.ErrKilled))):
			record()
		}
		finish()
		if resp != nil && resp.Request == sent {
			resp.Request = req
		}
		return resp, err
	}
}

// replayKey marks the context of a request made again after a pooled
// connection turned out closed (see IsReplay).
type replayKey struct{}

// IsReplay says ctx is that of a request made again on a connection of its
// own after a pooled one turned out closed: the request was let go, and
// listed, before any stop; the kill file does not stop it halfway.
func IsReplay(ctx context.Context) bool { return ctx.Value(replayKey{}) != nil }

// maxReplays is how many times a request is made again after a pooled
// connection turned out closed: the replay is on a connection of its own,
// which cannot be one of those.
const maxReplays = 1

// fresh is Base, with no connection kept: what a replay is sent with.
func (t *Transport) fresh() http.RoundTripper {
	t.freshOnce.Do(func() {
		t.freshRT = t.base()
		if tr, ok := t.base().(*http.Transport); ok {
			c := tr.Clone()
			c.DisableKeepAlives = true
			t.freshRT = c
		}
	})
	return t.freshRT
}

// closedByPeer says err is what a request gets from a connection the other
// end had already closed.
func closedByPeer(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	return strings.Contains(err.Error(), "server closed idle connection")
}

func (t *Transport) base() http.RoundTripper {
	if t.Base == nil {
		return noBase{}
	}
	return t.Base
}

// noBase is what a Transport without a Base sends with: an error. Only
// egress makes the transports a run sends with, and gives each a Base.
type noBase struct{}

func (noBase) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("ledger: the transport has no Base to send with")
}

// CloseIdleConnections passes on to Base, as http.Client looks for it.
func (t *Transport) CloseIdleConnections() {
	if c, ok := t.base().(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Wrap is rt with its requests recorded; a
// transport already wrapped is returned as it is.
func Wrap(rt http.RoundTripper) http.RoundTripper { return WrapAs(ClassTarget, rt) }

// WrapAs is Wrap for requests of another class.
func WrapAs(class string, rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*Transport); ok {
		return t
	}
	return &Transport{Base: rt, Class: class}
}

// Unwrap is the transport under Wrap's, or rt itself.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*Transport); ok {
		return t.base()
	}
	return rt
}
