package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// PortDialer opens the TCP connections and UDP sockets of a port scan. Each
// one is refused once the kill file exists and for an address, or the name
// it was found under, outside the scope; each is entered in the ledger
// before it is made. The scanner counts them against the budget (Take) and
// paces them: it knows which of its connects are one more port and which
// are the same port asked again.
type PortDialer struct {
	timeout time.Duration
	src     net.IP
	via     proxy.ContextDialer // SOCKS5 for the connects of the scan itself; nil: direct
	socks   string              // its address, and the user:password it takes
	auth    string
	preMu   sync.Mutex
	pre     map[string]int // connects Reserve recorded for an address, until their TCP calls
}

// NewPortDialer is a dialer with a timeout per connect, connecting from
// the local address src (nil: the system's; a target of the other family is
// asked from the system's) and, when socks5 is host:port, through that
// SOCKS5 proxy (auth is "user:password" for it).
func NewPortDialer(timeout time.Duration, src net.IP, socks5, auth string) *PortDialer {
	d := &PortDialer{timeout: timeout, src: src, socks: socks5, auth: auth}
	if socks5 != "" {
		var a *proxy.Auth
		if u, p, ok := strings.Cut(auth, ":"); ok || u != "" {
			a = &proxy.Auth{User: u, Password: p}
		}
		if pd, err := proxy.SOCKS5("tcp", socks5, a, &net.Dialer{Timeout: timeout}); err == nil {
			d.via, _ = pd.(proxy.ContextDialer)
		}
	}
	return d
}

// ProxyError is a connect that failed at the proxy, not at its target: the
// proxy was not reached, or it broke the SOCKS exchange. It is no answer of
// the port, so a scan stops on it instead of calling every port closed.
type ProxyError struct {
	Proxy string
	Err   error
}

func (e *ProxyError) Error() string { return "-proxy " + e.Proxy + " failed: " + proxyReason(e.Err) }
func (e *ProxyError) Unwrap() error { return e.Err }

// proxyReason is what went wrong at the proxy, without the layers of the
// SOCKS client's wrapping.
func proxyReason(err error) string {
	var oe *net.OpError
	for errors.As(err, &oe) && oe.Err != nil {
		err = oe.Err
	}
	return err.Error()
}

// proxyFailed tells an error of the proxy from the proxy's report of its
// target: a SOCKS reply ("connection refused", "host unreachable") and a wait
// that timed out are the target's; a refused dial of the proxy, a closed
// connection or a protocol or authentication error are the proxy's.
func proxyFailed(err error) bool {
	var oe *net.OpError
	if !errors.As(err, &oe) || !strings.HasPrefix(oe.Op, "socks") {
		return false
	}
	var inner *net.OpError
	if errors.As(oe.Err, &inner) && inner.Op == "dial" {
		return true // the proxy itself, even when it timed out
	}
	if strings.HasPrefix(oe.Err.Error(), "unknown error ") {
		return false // the proxy's reply about the target
	}
	var ne net.Error
	return !(errors.As(oe.Err, &ne) && ne.Timeout()) && !errors.Is(oe.Err, context.DeadlineExceeded)
}

// CanBindSource says ip can be the source of a scan's connects: a socket binds
// to it. An address that is not one of this machine's cannot, and no port
// would be asked from it.
func CanBindSource(ip net.IP) error {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Err != nil {
			return oe.Err // the system's words, without the address again
		}
		return err
	}
	return l.Close()
}

// Proxied says the scan's own connects go through a proxy.
func (d *PortDialer) Proxied() bool { return d.via != nil }

// allowed refuses a connect once the kill file exists, or when neither the
// name an address was found under nor the address is in the scope, or the
// port is not the one -allow names for the host.
func (d *PortDialer) allowed(host, addr string) error {
	if err := Current().Killed(); err != nil {
		return err
	}
	return d.inScope(host, addr)
}

// inScope is allowed without the kill file.
func (d *PortDialer) inScope(host, addr string) error {
	p := Current()
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}
	if p.Scope() == nil {
		// No rule: only a host the targets name with other ports is held, by
		// the name asked for, else by the address.
		name := ip
		if host != "" {
			name = host
		}
		if p.heldByTargets(name, port) {
			return neterr.ErrOutOfTargetPort
		}
		return nil
	}
	// A name is in scope by its rule, an address by its own or its range's.
	if p.AllowsAddr(ip, port) || (host != "" && p.AllowsAddr(host, port)) {
		return nil
	}
	if p.Allows(ip) || (host != "" && p.Allows(host)) {
		return neterr.ErrOutOfPort
	}
	return neterr.ErrOutOfScope
}

func (d *PortDialer) netDialer(ip string) net.Dialer {
	nd := net.Dialer{Timeout: d.timeout}
	if d.src != nil {
		if t := net.ParseIP(ip); t != nil && (t.To4() == nil) == (d.src.To4() == nil) {
			nd.LocalAddr = &net.TCPAddr{IP: d.src}
		}
	}
	return nd
}

func hostOfAddr(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// TCP connects to addr (ip:port) of host ("" when only the address is
// known), through the proxy when there is one. Its ledger line is made as
// the connect begins; a connect that never began (the scope, the kill file or
// the end of ctx came first) has none and is given back to the budget, which
// the caller counted.
func (d *PortDialer) TCP(ctx context.Context, host, addr string) (net.Conn, error) {
	reserved := d.takeReserved(addr)
	if !reserved {
		if err := d.allowed(host, addr); err != nil {
			Refund()
			return nil, err
		}
	}
	return d.listed(ctx, host, addr, false)(d.connect(ctx, host, addr, reserved, false))
}

// connect makes the connect to addr: its line is the ledger's when the
// socket is about to connect (reserved: Reserve wrote it, and a stop that
// came since waits until the connect has begun), and a connect that never
// begun is given back.
func (d *PortDialer) connect(ctx context.Context, host, addr string, reserved, direct bool) (net.Conn, error) {
	rec := func() { ledger.TCP(ctx, host, addr) }
	if reserved {
		rec = func() {}
	}
	c, began, err := connectTracked(ctx, d.netDialer(hostOfAddr(addr)), reserved, rec, func(dctx context.Context, nd *net.Dialer) (net.Conn, error) {
		if d.socks != "" && !direct {
			var a *proxy.Auth
			if u, p, ok := strings.Cut(d.auth, ":"); ok || u != "" {
				a = &proxy.Auth{User: u, Password: p}
			}
			pd, err := proxy.SOCKS5("tcp", d.socks, a, &net.Dialer{Timeout: d.timeout, Control: nd.Control})
			if err != nil {
				return nil, err
			}
			cctx, cancel := context.WithTimeout(dctx, d.timeout)
			defer cancel()
			c, err := pd.(proxy.ContextDialer).DialContext(cctx, "tcp", addr)
			if err != nil && dctx.Err() == nil && proxyFailed(err) {
				err = &ProxyError{Proxy: d.socks, Err: err}
			}
			return c, err
		}
		return dialResolvedWith(dctx, Current(), nd, "tcp", addr)
	})
	if !began {
		Refund() // counted by the caller, never connected
	}
	return c, err
}

// Reserve records the connects a scan is about to make to addrs (ip:port),
// those the scope allows, in one write of the ledger, and does not stop
// them after: a connect a line was made for goes out even if the kill file
// or the end of ctx comes first, and is held by neither until its connect has
// begun. Nothing is recorded once either has come: the scan's connects are
// then refused one by one at their TCP call and given back. The scanner counts
// the connects before it reserves them.
func (d *PortDialer) Reserve(ctx context.Context, host string, addrs []string) {
	if ctx.Err() != nil || Current().Killed() != nil {
		return
	}
	ok := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if d.inScope(host, a) == nil {
			ok = append(ok, a)
		}
	}
	ledger.TCPBatch(ctx, host, ok)
	d.preMu.Lock()
	defer d.preMu.Unlock()
	if d.pre == nil {
		d.pre = map[string]int{}
	}
	for _, a := range ok {
		d.pre[a]++ // two scans of one address reserve it twice, and connect twice
	}
}

// takeReserved says a connect to addr was recorded by Reserve, and uses it up.
func (d *PortDialer) takeReserved(addr string) bool {
	d.preMu.Lock()
	defer d.preMu.Unlock()
	return d.takeLocked(addr)
}

// takeReservedMany is takeReserved for each of addrs, under one lock: got[i]
// says whether addrs[i] was reserved. A batch of connects takes its places at
// once, not with a lock for each that all the batches in flight wait on.
func (d *PortDialer) takeReservedMany(addrs []string, got []bool) {
	d.preMu.Lock()
	defer d.preMu.Unlock()
	for i, a := range addrs {
		got[i] = d.takeLocked(a)
	}
}

func (d *PortDialer) takeLocked(addr string) bool {
	n := d.pre[addr]
	switch {
	case n == 0:
		return false
	case n == 1:
		delete(d.pre, addr) // a used entry is not kept: a full range left 65,535
	default:
		d.pre[addr] = n - 1
	}
	return true
}

// TCPDirect is TCP that never goes through the proxy: the service probes
// dial on their own.
func (d *PortDialer) TCPDirect(ctx context.Context, host, addr string) (net.Conn, error) {
	if err := d.allowed(host, addr); err != nil {
		Refund()
		return nil, err
	}
	return d.listed(ctx, host, addr, false)(d.connect(ctx, host, addr, false, true))
}

// listed wraps the connection a dial returns so that what is written to it
// is entered in the ledger, probe by probe; secure says it is inside TLS.
func (d *PortDialer) listed(ctx context.Context, host, addr string, secure bool) func(net.Conn, error) (net.Conn, error) {
	return func(c net.Conn, err error) (net.Conn, error) {
		if err != nil || c == nil {
			return c, err
		}
		return ledger.WrapProbes(ctx, ledger.ClassTarget, host, addr, secure, c), nil
	}
}

// TLS is TCPDirect with a TLS handshake that waits at most handshake.
func (d *PortDialer) TLS(ctx context.Context, host, addr string, cfg *tls.Config, handshake time.Duration) (net.Conn, error) {
	return d.tls(ctx, host, addr, cfg, handshake, false)
}

// TLSLegacy is TLS with the fallback client (see legacytls.go): for a server
// crypto/tls failed with an error LegacyTLSNeeded names. It is another
// connection, recorded like any other, and the caller counts and paces it.
func (d *PortDialer) TLSLegacy(ctx context.Context, host, addr string, cfg *tls.Config, handshake time.Duration) (net.Conn, error) {
	return d.tls(ctx, host, addr, cfg, handshake, true)
}

func (d *PortDialer) tls(ctx context.Context, host, addr string, cfg *tls.Config, handshake time.Duration, legacy bool) (net.Conn, error) {
	if err := d.allowed(host, addr); err != nil {
		Refund()
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	// The name is looked up by the run's resolver, not the dialer's.
	c, err := d.connectTLS(hctx, host, addr)
	if err != nil {
		return nil, err
	}
	cfg = cfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = hostOfAddr(addr)
	}
	if legacy {
		lc, err := legacyClient(hctx, c, cfg, hostOfAddr(addr))
		if err != nil {
			c.Close()
			return nil, err
		}
		return d.listed(ctx, host, addr, true)(lc, nil)
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, err
	}
	return d.listed(ctx, host, addr, true)(tc, nil)
}

// connectTLS is the connect of a handshake: the line of a plain direct one.
func (d *PortDialer) connectTLS(ctx context.Context, host, addr string) (net.Conn, error) {
	return d.connect(ctx, host, addr, false, true)
}

// UDP opens a socket connected to raddr, which is a datagram about to be
// sent to it: its ledger line is made once the socket is open, and the caller
// writes the datagram at once, which nothing stops. A socket that could not
// be opened has no line and is given back to the budget, which the caller
// counted.
func (d *PortDialer) UDP(ctx context.Context, host string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if err := d.allowed(host, raddr.String()); err != nil {
		Refund()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		Refund()
		return nil, err
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		Refund()
		return nil, err
	}
	ledger.UDP(ctx, host, raddr.String())
	return c, nil
}

// UDPAnySource is UDP for a service that answers from a port of its own: the
// socket is not connected to raddr.
func (d *PortDialer) UDPAnySource(ctx context.Context, host string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if err := d.allowed(host, raddr.String()); err != nil {
		Refund()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		Refund()
		return nil, err
	}
	c, err := listenAnySource(raddr)
	if err != nil {
		Refund()
		return nil, err
	}
	ledger.UDP(ctx, host, raddr.String())
	return c, nil
}

// DialTLS connects to addr (host:port) of a target and runs the TLS
// handshake, observing whatever certificate it presents: one handshake, one
// ledger line, held to the kill file and the scope.
func DialTLS(ctx context.Context, host, addr string, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	return (&PortDialer{timeout: timeout}).TLS(ctx, host, addr, cfg, timeout)
}

// DialTLSLegacy is DialTLS with the fallback client, for a server crypto/tls
// failed with an error LegacyTLSNeeded names: another connection and ledger
// line, which the caller counts.
func DialTLSLegacy(ctx context.Context, host, addr string, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	return (&PortDialer{timeout: timeout}).TLSLegacy(ctx, host, addr, cfg, timeout)
}
