package egress

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/scope"
)

// portScope holds the policy to 127.0.0.1 on one port: -allow 127.0.0.1:PORT.
func portScope(t *testing.T, allowed *httptest.Server) (other *httptest.Server, otherHits func() int32) {
	t.Helper()
	u, _ := url.Parse(allowed.URL)
	rules := scope.Rules{Allow: []string{"127.0.0.1:" + u.Port()}}.Compile()
	SetScope(rules.Allows)
	SetScopeAddr(rules.AllowsAddr)
	srv, n := counting(t)
	return srv, n.Load
}

// -allow HOST:PORT allows that host on that port only, at every place that
// connects: the HTTP client (also through a proxy, which sees only its own
// address), a raw dial, a port scan's connect, Chrome's guard.
func TestAllowPortHoldsEveryConnection(t *testing.T) {
	Reset()
	defer Reset()
	good, goodHits := counting(t)
	bad, badHits := portScope(t, good)
	ctx := context.Background()

	c := TargetClient(TargetOptions{})
	if err := get(c, good.URL+"/"); err != nil || goodHits.Load() != 1 {
		t.Fatalf("the allowed port: %v, %d hits", err, goodHits.Load())
	}
	err := get(c, bad.URL+"/")
	if !errors.Is(err, neterr.ErrOutOfScope) || !errors.Is(err, neterr.ErrOutOfPort) || badHits() != 0 {
		t.Fatalf("the same host on another port: %v, %d hits", err, badHits())
	}

	// A proxy is the connection; the request's own port is what is held.
	proxy, proxied := counting(t)
	pc := TargetClient(TargetOptions{Proxy: mustParse(t, proxy.URL)})
	if err := get(pc, bad.URL+"/"); !errors.Is(err, neterr.ErrOutOfPort) || proxied.Load() != 0 {
		t.Fatalf("through a proxy: %v, the proxy got %d", err, proxied.Load())
	}

	badAddr := bad.Listener.Addr().String()
	if _, err := DialTarget(ctx, "tcp", badAddr); !errors.Is(err, neterr.ErrOutOfPort) {
		t.Fatalf("a dial: %v", err)
	}
	if cn, err := DialTarget(ctx, "tcp", good.Listener.Addr().String()); err != nil {
		t.Fatalf("a dial to the allowed port: %v", err)
	} else {
		cn.Close()
	}

	d := NewPortDialer(time.Second, nil, "", "")
	if _, err := d.TCP(ctx, "", badAddr); !errors.Is(err, neterr.ErrOutOfPort) {
		t.Fatalf("a port scan's connect: %v", err)
	}
	if cn, err := d.TCP(ctx, "", good.Listener.Addr().String()); err != nil {
		t.Fatalf("a port scan's connect to the allowed port: %v", err)
	} else {
		cn.Close()
	}
	if _, err := d.UDP(ctx, "", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}); !errors.Is(err, neterr.ErrOutOfPort) {
		t.Fatalf("a UDP probe: %v", err)
	}
}

func TestChromeGuardHoldsThePort(t *testing.T) {
	Reset()
	defer Reset()
	good, goodHits := counting(t)
	bad, badHits := portScope(t, good)
	g, err := NewChromeGuard(func(h string) bool { return h == "127.0.0.1" })
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Chrome(os.Getpid())
	viaGuard(t, g.Addr(), good.Listener.Addr().String())
	viaGuard(t, g.Addr(), bad.Listener.Addr().String())
	if goodHits.Load() != 1 || badHits() != 0 {
		t.Fatalf("the allowed port got %d requests, the other %d", goodHits.Load(), badHits())
	}
	if n, hosts := g.Denied(); n != 1 || len(hosts) != 1 || hosts[0] != bad.Listener.Addr().String() {
		t.Fatalf("denied %d %v, want the other port counted by host:port", n, hosts)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
