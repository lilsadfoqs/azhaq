package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// DialTarget connects to a target as the run's HTTP client does: a name
// goes to the addresses the run's resolver found for it, IPv6 first where
// the machine has a route and IPv4 after a short head start (RFC 8305).
// It refuses once the kill file exists and for a host outside the scope.
func DialTarget(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if err := Current().CheckAddr(host, port); err != nil {
			return nil, err
		}
	}
	return dialThrough(ctx, network, addr)
}

// DialProxy connects to a proxy the user named (-proxy, -chrome-proxy):
// not a target, so not held to the scope; the kill file still stops it.
func DialProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialThrough(ctx, network, addr)
}

// dialThrough is the dial of a target's transport: the scope is checked
// for each request, not for a connection, which may be to a proxy.
func dialThrough(ctx context.Context, network, addr string) (net.Conn, error) {
	p := Current()
	if err := p.Killed(); err != nil {
		return nil, err
	}
	return dialResolved(ctx, p, network, addr)
}

// DialSource connects to a third-party service (a mail server, a database
// of a source): not the scope's business, the kill file stops it, and the
// connection is recorded as a source's.
func DialSource(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := Current().Killed(); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 30 * time.Second}
	c, _, err := connectTracked(ctx, d, false, func() { ledger.TCPAs(ctx, ledger.ClassSource, "", addr) },
		func(dctx context.Context, nd *net.Dialer) (net.Conn, error) {
			return nd.DialContext(dctx, network, addr)
		})
	return c, err
}

// DialSourceTLS is DialSource with an implicit TLS handshake (SMTPS).
func DialSourceTLS(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
	c, err := DialSource(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func pinnedDial(ip string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if err := Current().Killed(); err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// dialResolved connects through the resolver's addresses when it has an
// answer, the way the system would. Some edges answer only one family
// from a given network.
func dialResolved(ctx context.Context, p *Policy, network, addr string) (net.Conn, error) {
	return dialResolvedWith(ctx, p, &net.Dialer{Timeout: 5 * time.Second}, network, addr)
}

// dialResolvedWith is dialResolved with the caller's dialer.
func dialResolvedWith(ctx context.Context, p *Policy, d *net.Dialer, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	ips := p.Resolve(ctx, host)
	if len(ips) == 0 {
		if p.resolverOnly() {
			return dialLoopbackName(ctx, d, network, host, port)
		}
		return d.DialContext(ctx, network, addr) // /etc/hosts, special-use names
	}
	var v4, v6 []string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	primary, fallback := v4, v6
	if ipv6Routable() && len(v6) > 0 {
		primary, fallback = v6, v4
	} else if !ipv6Routable() {
		fallback = nil
	}
	if len(primary) == 0 {
		primary, fallback = fallback, nil
	}
	return dialEither(ctx, d, network, port, primary, fallback)
}

// dialLoopbackName is the dial of a name the user's resolvers have no
// address for: localhost is loopback by RFC 6761 and needs no lookup (a
// proxy on localhost), any other name is unresolved, and the system's
// resolver is not asked.
func dialLoopbackName(ctx context.Context, d *net.Dialer, network, host, port string) (net.Conn, error) {
	if h := strings.TrimSuffix(strings.ToLower(host), "."); h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return dialEither(ctx, d, network, port, []string{"127.0.0.1"}, []string{"::1"})
	}
	return nil, &net.DNSError{Err: "no address from the resolvers given with -resolvers (the system's resolver is not asked)", Name: host, IsNotFound: true}
}

// fallbackDelay is the head start of the preferred address family.
const fallbackDelay = 300 * time.Millisecond

// dialEither tries primary addresses in order and, from fallbackDelay on,
// the fallback ones alongside; the first connection wins.
func dialEither(ctx context.Context, d *net.Dialer, network, port string, primary, fallback []string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, 2)
	try := func(ips []string, wait time.Duration) {
		if wait > 0 {
			select {
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			case <-time.After(wait):
			}
		}
		var last error
		for _, ip := range ips {
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				results <- result{c: c}
				return
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		results <- result{err: last}
	}
	n := 1
	go try(primary, 0)
	if len(fallback) > 0 {
		n++
		go try(fallback, fallbackDelay)
	}
	var first error
	for i := 0; i < n; i++ {
		r := <-results
		if r.err == nil {
			cancel()
			// The other attempt may still connect: close what it opens.
			go func(left int) {
				for j := 0; j < left; j++ {
					if r := <-results; r.c != nil {
						r.c.Close()
					}
				}
			}(n - i - 1)
			return r.c, nil
		}
		if first == nil {
			first = r.err
		}
	}
	return nil, first
}

// IPv6Routable says whether this machine can reach IPv6 addresses on the
// internet.
func IPv6Routable() bool { return ipv6Routable() }

var ipv6Routable = sync.OnceValue(func() bool {
	// A UDP "connection" sends nothing; it only asks the kernel for a
	// route and a source address.
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
})

// ConnectTarget opens a raw connection to a target (a probe that speaks a
// protocol of its own: JARM, pipelining) and records it in the ledger as a
// connect, as the connect begins. It is held to the scope and the kill file;
// the caller counts it with Spend, and a connect that never began (refused,
// stopped, or the name had no address) is given back.
func ConnectTarget(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if err := Current().CheckAddr(host, port); err != nil {
			Refund()
			return nil, err
		}
	}
	p := Current()
	if err := p.Killed(); err != nil {
		Refund()
		return nil, err
	}
	c, began, err := connectTracked(ctx, net.Dialer{Timeout: 5 * time.Second}, false, func() { ledger.TCP(ctx, host, addr) },
		func(dctx context.Context, nd *net.Dialer) (net.Conn, error) {
			return dialResolvedWith(dctx, p, nd, "tcp", addr)
		})
	if !began {
		Refund()
	}
	return c, err
}

// connectTracked runs dial with nd made to call rec once, when the first
// connect is about to be made: a line made then is for a connect that was
// attempted, and none is made when the dial fails before (no address, a
// stopped ctx, no socket). began says whether it was. With hold, a ctx that
// ends before then does not stop the dial: whoever holds a line already
// made for this connect needs it to go out; one that ends after stops it
// as usual.
func connectTracked(ctx context.Context, nd net.Dialer, hold bool, rec func(), dial func(context.Context, *net.Dialer) (net.Conn, error)) (c net.Conn, began bool, err error) {
	var begun atomic.Bool
	dctx, cancel := ctx, context.CancelFunc(func() {})
	if hold {
		dctx, cancel = context.WithCancel(context.WithoutCancel(ctx))
		stop := context.AfterFunc(ctx, func() {
			if begun.Load() {
				cancel()
			}
		})
		defer stop()
	}
	defer cancel()
	prev := nd.Control
	var once sync.Once
	nd.Control = func(network, address string, rc syscall.RawConn) error {
		once.Do(func() {
			rec()
			begun.Store(true)
			if hold && ctx.Err() != nil {
				cancel()
			}
		})
		if prev != nil {
			return prev(network, address, rc)
		}
		return nil
	}
	c, err = dial(dctx, &nd)
	return c, begun.Load(), err
}

// ConnectTargetTLS is ConnectTarget with a TLS handshake that takes any
// certificate. A server crypto/tls cannot handshake with (see legacytls.go)
// gets a second connection, counted like the first, with the fallback client.
func ConnectTargetTLS(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
	c, err := ConnectTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		if !LegacyTLSNeeded(err) || cfg == nil || !cfg.InsecureSkipVerify || Spend(ctx) != nil {
			return nil, err
		}
		c2, cerr := ConnectTarget(ctx, addr)
		if cerr != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		lc, lerr := legacyClient(ctx, c2, cfg, host)
		if lerr != nil {
			c2.Close()
			return nil, fmt.Errorf("%w; fallback TLS client: %v", err, lerr)
		}
		return lc, nil
	}
	return tc, nil
}
