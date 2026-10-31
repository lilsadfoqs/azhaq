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

	"github.com/trannghiach/azhaq/internal/neterr"
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
		e.Rule = l.rule(host)
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

// Unsent is called for a request Transport held back after it was counted
// (fetch gives it back to the budget).
var Unsent func()

// Chrome records a request Chrome sent. ctx may be nil.
func Chrome(ctx context.Context, method, raw string) { ChromeAt(ctx, method, raw, time.Time{}) }

// ChromeAt is Chrome for a request sent at a time already past; zero is now.
func ChromeAt(ctx context.Context, method, raw string, at time.Time) {
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
		Rule: l.rule(host), Collector: collectorOf(ctx)})
}

// TCP records a connection about to be made to a target at addr (ip:port).
// host is the name it was found under, "" when only the address is known.
func TCP(ctx context.Context, host, addr string) { TCPAs(ctx, ClassTarget, host, addr) }

// TCPAs is TCP for a connection of another class.
func TCPAs(ctx context.Context, class, host, addr string) {
	counter(class).Add(1)
	l := Active()
	if l == nil {
		return
	}
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	name := host
	if name == "" {
		name = ip
	}
	var rule string
	if class == ClassTarget {
		if rule = l.rule(name); rule == "" && name != ip {
			rule = l.rule(ip)
		}
	}
	l.Record(Entry{Kind: "tcp", Class: class, Target: addr, Host: host, Rule: rule, Collector: collectorOf(ctx)})
}

// DNS records a query about to be sent to a resolver: the name, its type
// ("A") and the resolver's address or URL.
func DNS(ctx context.Context, name, qtype, server string) {
	l := Active()
	if l == nil {
		return
	}
	l.Record(Entry{Kind: "dns", Class: ClassDNS, Method: qtype, Target: server, Host: name, Rule: l.rule(name), Collector: collectorOf(ctx)})
}

// Transport records each request as it is written to its connection, and
// one that fails to get a connection after it, so a request that fails
// still appears and one that never left does not. Class is what the
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
	if l := Active(); l != nil && class == ClassTarget && req.URL != nil && !Safe(req.Method) && l.refused(req.Method, req.URL.Redacted(), bodySum(req), false) {
		if req.Body != nil {
			req.Body.Close()
		}
		if Unsent != nil {
			Unsent()
		}
		return nil, neterr.ErrNotRepeated
	}
	var once sync.Once
	record := func() { once.Do(func() { HTTPAs(class, req) }) }
	for try := 0; ; try++ {
		var reused, skipped, answered bool
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				reused = info.Reused
				if info.Reused && t.Dead != nil && info.Conn != nil && t.Dead(info.Conn) {
					// Closed under the pool: nothing is written to it.
					skipped = true
					info.Conn.Close()
					return
				}
				record() // the first live connection: later ones are a replay of it
			},
			GotFirstResponseByte: func() { answered = true },
		}
		sent := req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		if try > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
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
		// the count hold it once.
		if err != nil && try < maxReplays && reused && (skipped || !answered && closedByPeer(err)) && req.Context().Err() == nil &&
			(req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
			continue
		}
		record() // no connection was reached (refused, timed out), or the transport reports none
		if resp != nil && resp.Request == sent {
			resp.Request = req
		}
		return resp, err
	}
}

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
