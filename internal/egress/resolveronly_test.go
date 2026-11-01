package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// systemDNS makes the system's resolver (net.DefaultResolver) a fake that
// answers every A question with 127.0.0.1, and counts what it is asked.
func systemDNS(t *testing.T) *atomic.Int32 {
	t.Helper()
	got, pc := new(atomic.Int32), mustUDP(t)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		got.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, pc.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; srv.Shutdown() })
	return got
}

func mustUDP(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	return pc
}

func noAnswer(context.Context, string) []string { return nil }

// A run whose resolvers the user named asks them for every name: a name they
// have no address for is not connected to, and the system's resolver is not
// asked in its place.
func TestResolverOnlyNeverFallsBackToTheSystem(t *testing.T) {
	Reset()
	defer Reset()
	asked := systemDNS(t)
	addr, accepted := listener(t)
	_, port, _ := net.SplitHostPort(addr)
	SetResolver(noAnswer)

	// By default the system's resolver still answers what the resolver does not.
	c, err := DialTarget(context.Background(), "tcp", net.JoinHostPort("sys.lab.test", port))
	if err != nil {
		t.Fatalf("the default falls back to the system: %v", err)
	}
	c.Close()
	if asked.Load() == 0 {
		t.Fatal("the default did not ask the system's resolver")
	}

	for i := 0; i < 100 && accepted.Load() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	asked.Store(0)
	before := accepted.Load()
	SetResolverOnly(true)
	_, err = DialTarget(context.Background(), "tcp", net.JoinHostPort("sys.lab.test", port))
	var de *net.DNSError
	if !errors.As(err, &de) || !neterr.UnknownHost(err) {
		t.Fatalf("a name the resolvers cannot answer: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if asked.Load() != 0 || accepted.Load() != before {
		t.Fatalf("the system's resolver was asked %d times and %d connections were made", asked.Load(), accepted.Load()-before)
	}
}

// localhost is loopback by definition (a proxy on localhost): it connects
// without a lookup by anyone.
func TestResolverOnlyConnectsToLocalhostWithoutALookup(t *testing.T) {
	Reset()
	defer Reset()
	asked := systemDNS(t)
	addr, accepted := listener(t)
	_, port, _ := net.SplitHostPort(addr)
	SetResolver(noAnswer)
	SetResolverOnly(true)
	c, err := DialTarget(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if asked.Load() != 0 {
		t.Fatalf("the system's resolver was asked %d times", asked.Load())
	}
	time.Sleep(20 * time.Millisecond)
	if accepted.Load() != 1 {
		t.Fatalf("%d connections", accepted.Load())
	}
}

// A port scan's and a TLS probe's connects name the host they were found
// under: it is looked up by the run's resolver, not the dialer's own.
func TestPortDialerLooksNamesUpWithTheRunsResolver(t *testing.T) {
	Reset()
	defer Reset()
	asked := systemDNS(t)
	addr, accepted := listener(t)
	_, port, _ := net.SplitHostPort(addr)
	var lookups atomic.Int32
	SetResolver(func(_ context.Context, host string) []string {
		lookups.Add(1)
		if host == "app.lab.test" {
			return []string{"127.0.0.1"}
		}
		return nil
	})
	SetResolverOnly(true)
	d := NewPortDialer(time.Second, nil, "", "")
	named := net.JoinHostPort("app.lab.test", port)
	if c, err := d.TCP(context.Background(), "app.lab.test", named); err != nil {
		t.Fatalf("TCP: %v", err)
	} else {
		c.Close()
	}
	if c, err := d.TCPDirect(context.Background(), "app.lab.test", named); err != nil {
		t.Fatalf("TCPDirect: %v", err)
	} else {
		c.Close()
	}
	// The listener closes at once: the handshake fails, after the connect.
	_, err := DialTLS(context.Background(), "app.lab.test", named, &tls.Config{InsecureSkipVerify: true}, time.Second)
	if err == nil {
		t.Fatal("a handshake with a listener that hangs up")
	}
	if lookups.Load() != 3 || asked.Load() != 0 {
		t.Fatalf("the run's resolver was asked %d times (want 3), the system's %d", lookups.Load(), asked.Load())
	}
	if _, err := d.TCP(context.Background(), "ghost.lab.test", net.JoinHostPort("ghost.lab.test", port)); !neterr.UnknownHost(err) {
		t.Fatalf("a name the resolver cannot answer: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if accepted.Load() != 3 {
		t.Fatalf("%d connections, want 3", accepted.Load())
	}
}

// Chrome's connections are made by the guard, which resolves a name through
// the run's resolver and no other.
func TestChromeGuardResolvesThroughTheRunsResolverOnly(t *testing.T) {
	Reset()
	defer Reset()
	asked := systemDNS(t)
	srv, hits := counting(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	SetResolver(func(_ context.Context, host string) []string {
		if host == "app.lab.test" {
			return []string{"127.0.0.1"}
		}
		return nil
	})
	SetResolverOnly(true)
	g, err := NewChromeGuard(func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Chrome(os.Getpid())
	for _, name := range []string{"app.lab.test", "ghost.lab.test"} {
		viaGuard(t, g.Addr(), net.JoinHostPort(name, port))
	}
	if hits.Load() != 1 || asked.Load() != 0 {
		t.Fatalf("the server saw %d requests (want 1, the resolvable name), the system's resolver was asked %d times", hits.Load(), asked.Load())
	}
}

// viaGuard sends one GET to target through the guard at addr, and reads what
// comes back or until the guard hangs up.
func viaGuard(t *testing.T, addr, target string) {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return // refused
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_, _ = io.Copy(io.Discard, c)
}
