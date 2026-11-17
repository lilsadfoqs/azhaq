package fetch

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Go's own TLS server answers plain bytes with no alert: it closes. A request
// to such a listener over http:// fails with a hint that the port may speak TLS.
func TestPlainRequestToARealTLSListener(t *testing.T) {
	Reset()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS() // only for its certificate
	defer srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr).String()
	_, _, err = Do(context.Background(), http.DefaultClient, "http://"+addr+"/")
	if err == nil || !strings.Contains(err.Error(), "this port may speak TLS; try https://"+addr) {
		t.Fatalf("no hint in %v", err)
	}
}

// A body cut short by EOF is no sign of TLS: the server answered.
func TestCutBodyIsNoTLSHint(t *testing.T) {
	Reset()
	addr := serveRaw(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort"))
	})
	_, _, err := Do(context.Background(), http.DefaultClient, "http://"+addr+"/")
	if err != nil && strings.Contains(err.Error(), "TLS") {
		t.Errorf("a cut body is hinted as TLS: %v", err)
	}
}
