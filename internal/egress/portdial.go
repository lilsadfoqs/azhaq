package egress

import (
	"context"
	"crypto/tls"
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
	pre     sync.Map            // addresses Reserve recorded, until their TCP call
}

// NewPortDialer is a dialer with a timeout per connect, connecting from
// the local address src (nil: the system's; a target of the other family is
// asked from the system's) and, when socks5 is host:port, through that
// SOCKS5 proxy (auth is "user:password" for it).
func NewPortDialer(timeout time.Duration, src net.IP, socks5, auth string) *PortDialer {
	d := &PortDialer{timeout: timeout, src: src}
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
	if p.Scope() == nil {
		return nil
	}
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
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
// known), through the proxy when there is one.
func (d *PortDialer) TCP(ctx context.Context, host, addr string) (net.Conn, error) {
	if _, done := d.pre.LoadAndDelete(addr); done {
		// Reserve checked the scope and recorded the line: the kill file only.
		if err := Current().Killed(); err != nil {
			return nil, err
		}
	} else {
		if err := d.allowed(host, addr); err != nil {
			return nil, err
		}
		ledger.TCP(ctx, host, addr)
	}
	if d.via != nil {
		cctx, cancel := context.WithTimeout(ctx, d.timeout)
		defer cancel()
		return d.via.DialContext(cctx, "tcp", addr)
	}
	nd := d.netDialer(hostOfAddr(addr))
	return dialResolvedWith(ctx, Current(), &nd, "tcp", addr)
}

// Reserve records the connects a scan is about to make to addrs (ip:port),
// those the scope allows, in one write of the ledger: each is a line before
// its connect goes, and the TCP call for it does not record it again. The
// kill file still stops each connect at its TCP call.
func (d *PortDialer) Reserve(ctx context.Context, host string, addrs []string) {
	ok := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if d.inScope(host, a) == nil {
			ok = append(ok, a)
		}
	}
	ledger.TCPBatch(ctx, host, ok)
	for _, a := range ok {
		d.pre.Store(a, struct{}{})
	}
}

// TCPDirect is TCP that never goes through the proxy: the service probes
// dial on their own.
func (d *PortDialer) TCPDirect(ctx context.Context, host, addr string) (net.Conn, error) {
	if err := d.allowed(host, addr); err != nil {
		return nil, err
	}
	ledger.TCP(ctx, host, addr)
	nd := d.netDialer(hostOfAddr(addr))
	return dialResolvedWith(ctx, Current(), &nd, "tcp", addr)
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
		return nil, err
	}
	ledger.TCP(ctx, host, addr)
	nd := d.netDialer(hostOfAddr(addr))
	hctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	// The name is looked up by the run's resolver, not the dialer's.
	c, err := dialResolvedWith(hctx, Current(), &nd, "tcp", addr)
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
		return lc, nil
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

// UDP opens a socket connected to raddr, which is a datagram about to be
// sent to it: the ledger has it first.
func (d *PortDialer) UDP(ctx context.Context, host string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if err := d.allowed(host, raddr.String()); err != nil {
		return nil, err
	}
	ledger.UDP(ctx, host, raddr.String())
	return net.DialUDP("udp", nil, raddr)
}

// UDPAnySource is UDP for a service that answers from a port of its own: the
// socket is not connected to raddr.
func (d *PortDialer) UDPAnySource(ctx context.Context, host string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if err := d.allowed(host, raddr.String()); err != nil {
		return nil, err
	}
	ledger.UDP(ctx, host, raddr.String())
	return listenAnySource(raddr)
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
