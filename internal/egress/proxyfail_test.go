package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A proxy that cannot be reached, or that closes on the SOCKS exchange, is a
// ProxyError; a proxy that reports its target refused is not: that is the
// port's answer.
func TestProxyFailureIsNotATargetRefusal(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()

	hangup, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { hangup.Close() })
	go func() {
		for {
			c, err := hangup.Accept()
			if err != nil {
				return
			}
			c.Close() // closes before the SOCKS greeting is answered
		}
	}()

	refusing, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { refusing.Close() })
	go func() {
		for {
			c, err := refusing.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				io.ReadFull(c, b[:3])
				c.Write([]byte{5, 0})
				c.Read(b)
				c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()

	for _, tt := range []struct {
		name, proxy string
		want        bool
	}{
		{"unreachable", dead, true},
		{"closes on the greeting", hangup.Addr().String(), true},
		{"target refused", refusing.Addr().String(), false},
	} {
		d := NewPortDialer(time.Second, nil, tt.proxy, "")
		_, err := d.TCP(context.Background(), "", "127.0.0.1:22")
		var pe *ProxyError
		if err == nil || errors.As(err, &pe) != tt.want {
			t.Errorf("%s: %T %v, want proxy error %v", tt.name, err, err, tt.want)
		}
	}
}

// A request whose connection to its proxy fails says which proxy, and is not
// taken for the target's refusal.
func TestADeadProxyIsNamedInTheError(t *testing.T) {
	Reset()
	defer Reset()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	pu, _ := url.Parse("http://" + dead)
	SetTargetProxy(pu)
	c := TargetClient(TargetOptions{Timeout: 3 * time.Second})
	_, err := c.Get("http://127.0.0.1:9/x")
	if err == nil {
		t.Fatal("a dead proxy answered")
	}
	if want := "proxy " + dead + ": connection refused"; !strings.Contains(err.Error(), want) {
		t.Errorf("%v: want %q in it", err, want)
	}
	var pe *neterr.ProxyUnreachable
	if !errors.As(err, &pe) || pe.Proxy != dead {
		t.Errorf("%T %v: want a ProxyUnreachable naming %s", err, err, dead)
	}
	if neterr.Refused(err) {
		t.Error("a dead proxy is the target's refusal")
	}
}
