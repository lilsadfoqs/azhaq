package fetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// serveRaw runs fn on each connection a loopback listener accepts.
func serveRaw(t *testing.T, fn func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fn(c)
		}
	}()
	return ln.Addr().String()
}

// A plain request to a port that answers it with a TLS alert says the port
// speaks TLS, and names the https URL to try.
func TestPlainRequestToATLSPortAnsweredWithAnAlert(t *testing.T) {
	Reset()
	// What an OpenSSL-style server writes to bytes that are not a ClientHello:
	// a fatal alert record (content type 0x15, TLS 1.0, handshake_failure).
	addr := serveRaw(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 512)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28})
	})
	_, _, err := Do(context.Background(), http.DefaultClient, "http://"+addr+"/")
	if err == nil || !strings.Contains(err.Error(), "this port speaks TLS; try https://"+addr) {
		t.Fatalf("no hint in %v", err)
	}
	if strings.Contains(err.Error(), "may speak") {
		t.Errorf("an alert record is certain, not a maybe: %v", err)
	}
	if !neterr.NotHTTP(err) {
		t.Errorf("the hint hides what the failure was: %v", err)
	}
}

// A bare reset right after the request is weaker evidence: it says may.
func TestPlainRequestResetMayBeTLS(t *testing.T) {
	Reset()
	addr := serveRaw(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = c.Read(buf)
		_ = c.(*net.TCPConn).SetLinger(0) // close sends a reset
		c.Close()
	})
	_, _, err := Do(context.Background(), http.DefaultClient, "http://"+addr+"/")
	if err == nil || !strings.Contains(err.Error(), "this port may speak TLS; try https://"+addr) {
		t.Fatalf("no hint in %v", err)
	}
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the hint hides the reset: %v", err)
	}
}

// Other failures, and requests over https, are left as they were.
func TestTLSHintOnlyForAPlainRequestThatShowsIt(t *testing.T) {
	for _, c := range []struct {
		raw string
		err error
	}{
		{"http://h:80/", errors.New("EOF")},
		{"http://h:80/", errors.New(`malformed HTTP response "SSH-2.0-OpenSSH_9.6"`)},
		{"https://h:443/", syscall.ECONNRESET},
		{"https://h:443/", errors.New(`malformed HTTP response "\x15\x03\x01\x00\x02\x02\x16"`)},
		{"http://h:80/", nil},
	} {
		if got := neterr.TLSHint(c.raw, c.err); got != c.err {
			t.Errorf("%s %v: changed to %v", c.raw, c.err, got)
		}
	}
	got := neterr.TLSHint("http://u:p@h/x", errors.New(`Get "http://h/x": malformed HTTP response "\x16\x03\x01"`))
	if got == nil || !strings.HasSuffix(got.Error(), "this port speaks TLS; try https://h:80") {
		t.Errorf("a URL with no port is asked on 80: %v", got)
	}
}
