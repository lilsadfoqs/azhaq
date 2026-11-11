package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// The first bytes of a connection tell TLS from plain HTTP, and a
// WebSocket from the rest.
func TestSniff(t *testing.T) {
	hello := func(protos ...string) []byte {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			_ = tls.Client(client, &tls.Config{ServerName: "x.test", NextProtos: protos, InsecureSkipVerify: true}).Handshake()
		}()
		buf := make([]byte, 1<<15)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.ReadAtLeast(server, buf, 5)
		for n < 5+(int(buf[3])<<8|int(buf[4])) {
			m, err := server.Read(buf[n:])
			if err != nil {
				break
			}
			n += m
		}
		server.Close()
		return buf[:n]
	}
	for _, c := range []struct {
		name    string
		in      []byte
		tls, ws bool
	}{
		{"get", []byte("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n"), false, false},
		{"websocket", []byte("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\n\r\n"), false, true},
		{"tls h2", hello("h2", "http/1.1"), true, false},
		{"tls websocket", hello("http/1.1"), true, true},
		{"tls no alpn", hello(), true, false},
	} {
		r := bufio.NewReaderSize(bytes.NewReader(c.in), 5+1<<14)
		tls, ws, err := sniff(r)
		if err != nil || tls != c.tls || ws != c.ws {
			t.Errorf("%s: tls %v ws %v, %v", c.name, tls, ws, err)
		}
		if rest, _ := io.ReadAll(r); !bytes.Equal(rest, c.in) {
			t.Errorf("%s: sniffing consumed the bytes", c.name)
		}
	}
}

// A connection through the guard reaches a host in the scope, and nothing
// else: the refused one is counted and never dialled.
func TestChromeGuardRelaysToTheScopeOnly(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	g, err := NewChromeGuard(func(h string) bool { return h == "127.0.0.1" })
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Chrome(os.Getpid()) // this process stands in for Chrome
	d, err := proxy.SOCKS5("tcp", g.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("a host in the scope: %v", err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if line, _ := bufio.NewReader(c).ReadString('\n'); !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("answer %q", line)
	}
	c.Close()
	if _, err := d.Dial("tcp", "192.0.2.1:80"); err == nil {
		t.Fatal("a host outside the scope was relayed")
	}
	// Chrome's own services, pointed at ChromeOff, are refused uncounted.
	if _, err := d.Dial("tcp", ChromeOff+":80"); err == nil {
		t.Fatal("ChromeOff was relayed")
	}
	if n, hosts := g.Denied(); n != 1 || len(hosts) != 1 || hosts[0] != "192.0.2.1" {
		t.Fatalf("denied %d %v", n, hosts)
	}
	if hits.Load() != 1 {
		t.Fatalf("the server saw %d requests, want 1", hits.Load())
	}
}

// A connection the guard cannot open after telling Chrome it could is kept
// with its reason, for the sign-in to name; a later one that works clears it.
func TestChromeGuardKeepsWhyADialFailed(t *testing.T) {
	Reset()
	defer Reset()
	SetResolver(func(context.Context, string) []string { return nil })
	SetResolverOnly(true)
	srv, _ := counting(t)
	g, err := NewChromeGuard(func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Chrome(os.Getpid())
	d, err := proxy.SOCKS5("tcp", g.Addr(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", "app.lab.internal:8080") // told it worked
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, _ = io.Copy(io.Discard, c) // closed once the dial failed
	c.Close()
	err = g.FailedDial("app.lab.internal:8080")
	if err == nil || !strings.Contains(err.Error(), "no address from the resolvers") {
		t.Fatalf("FailedDial: %v", err)
	}
	if f := g.DialFailures(); len(f) != 1 || !strings.HasPrefix(f[0], "app.lab.internal:8080: ") {
		t.Fatalf("DialFailures: %v", f)
	}
	addr := srv.Listener.Addr().String()
	g.dialFailed(addr, errors.New("earlier"))
	c, err = d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_, _ = io.Copy(io.Discard, c)
	c.Close()
	if err := g.FailedDial(addr); err != nil {
		t.Fatalf("a dial that worked left %v", err)
	}
}
