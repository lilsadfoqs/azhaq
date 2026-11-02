package egress

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/tlstest"
)

func fetchBody(t *testing.T, c *http.Client, raw string) (*http.Response, string, error) {
	t.Helper()
	resp, err := c.Get(raw)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b), nil
}

// crypto/tls cannot handshake with a server whose suites are RSA key
// exchange or DHE; the fallback client does, and says what it negotiated.
func TestLegacyClientHandshakesWhatCryptoTLSCannot(t *testing.T) {
	for name, suite := range map[string]uint16{"rsa-gcm": tlstest.RSAGCM, "rsa-cbc": tlstest.RSACBC, "dhe-gcm": tlstest.DHEGCM, "dhe-cbc": tlstest.DHECBC} {
		t.Run(name, func(t *testing.T) {
			srv := tlstest.Serve(t, 0, 0, suite)
			_, err := tls.Dial("tcp", srv.Addr, &tls.Config{InsecureSkipVerify: true})
			if err == nil || !LegacyTLSNeeded(err) {
				t.Fatalf("crypto/tls: %v", err)
			}
			conn, err := net.Dial("tcp", srv.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			lc, err := legacyClient(t.Context(), conn, &tls.Config{InsecureSkipVerify: true}, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			st := lc.ConnectionState()
			if st.Version != tls.VersionTLS12 || st.CipherSuite != suite || len(st.PeerCertificates) != 1 || st.PeerCertificates[0].Subject.CommonName != "legacy.test" {
				t.Errorf("state %+v", st)
			}
			if n := CipherSuiteName(suite); strings.HasPrefix(n, "0x") {
				t.Errorf("suite %#x has no name", suite)
			}
		})
	}
}

// A client of targets reaches such a server as it reaches any: the same
// request goes again on a connection of the fallback client, the ledger has
// it once, the response says the version and suite, and a second request
// does not first fail with crypto/tls.
func TestTargetClientFallsBackAfterAHandshakeFailure(t *testing.T) {
	Reset()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil); l.Close() })
	for name, suite := range map[string]uint16{"rsa": tlstest.RSAGCM, "dhe": tlstest.DHEGCM} {
		srv := tlstest.Serve(t, 0, 0, suite)
		c := TargetClient(TargetOptions{})
		resp, body, err := fetchBody(t, c, "https://"+srv.Addr+"/")
		if err != nil || resp.StatusCode != 200 || body != tlstest.Reply {
			t.Fatalf("%s: %v %v %q", name, err, resp, body)
		}
		if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS12 || resp.TLS.CipherSuite != suite || len(resp.TLS.PeerCertificates) != 1 {
			t.Errorf("%s: response TLS %+v", name, resp.TLS)
		}
		if _, body, err = fetchBody(t, c, "https://"+srv.Addr+"/again"); err != nil || body != tlstest.Reply {
			t.Fatalf("%s second: %v %q", name, err, body)
		}
		if got := srv.Requests.Load(); got != 2 {
			t.Errorf("%s: the server read %d requests", name, got)
		}
		// One failed handshake of crypto/tls, then only the fallback's connections.
		if got := srv.Conns.Load(); got > 3 {
			t.Errorf("%s: %d connections for 2 requests", name, got)
		}
		if _, err := c.Post("https://"+srv.Addr+"/post", "text/plain", bytes.NewReader([]byte("12345"))); err != nil {
			t.Fatalf("%s post: %v", name, err)
		}
	}
	l.Close()
	n := 0
	_ = ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "http" {
			n++
		}
		return nil
	})
	if n != 6 {
		t.Errorf("the ledger has %d requests for 6", n)
	}
}

// A POST whose handshake failed is sent once: its body goes on the second
// connection, whole.
func TestFallbackSendsABodyOnce(t *testing.T) {
	Reset()
	srv := tlstest.Serve(t, 0, 0, tlstest.RSAGCM)
	resp, err := TargetClient(TargetOptions{}).Post("https://"+srv.Addr+"/", "text/plain", bytes.NewReader([]byte("0123456789")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Body") != "10" || srv.Requests.Load() != 1 {
		t.Errorf("body bytes %q, requests %d", resp.Header.Get("X-Body"), srv.Requests.Load())
	}
}

// A server crypto/tls handshakes with is not asked twice, and a TLS failure
// the fallback cannot cure keeps its reason.
func TestFallbackLeavesAModernServerAndKeepsTheReason(t *testing.T) {
	Reset()
	modern := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "modern") }))
	defer modern.Close()
	var conns int
	modern.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns++
		}
	}
	c := TargetClient(TargetOptions{})
	resp, body, err := fetchBody(t, c, modern.URL+"/")
	if err != nil || body != "modern" || resp.TLS == nil || conns != 1 {
		t.Fatalf("%v %q %v %d connections", err, body, resp, conns)
	}
	// TLS 1.1 only: below the 1.2 the client asks for, whoever the client is.
	old := tlstest.Serve(t, tls.VersionTLS10, tls.VersionTLS11, tlstest.RSACBC)
	_, _, err = fetchBody(t, c, "https://"+old.Addr+"/")
	if err == nil || !strings.Contains(err.Error(), "tls:") {
		t.Fatalf("error %v", err)
	}
	t.Logf("TLS 1.1 server: %v", err)
}

// Through an HTTP proxy the handshake runs over the CONNECT tunnel: the
// fallback opens its own tunnel, with the proxy's credentials, and the
// request is still one.
func TestFallbackGoesThroughTheProxy(t *testing.T) {
	Reset()
	srv := tlstest.Serve(t, 0, 0, tlstest.RSAGCM)
	var connects, withAuth atomic.Int32
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				connects.Add(1)
				if req.Header.Get("Proxy-Authorization") != "" {
					withAuth.Add(1)
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	pu, _ := url.Parse("http://user:pw@" + pl.Addr().String())
	c := TargetClient(TargetOptions{Proxy: pu})
	resp, body, err := fetchBody(t, c, "https://"+srv.Addr+"/")
	if err != nil || body != tlstest.Reply || resp.TLS == nil || resp.TLS.CipherSuite != tlstest.RSAGCM {
		t.Fatalf("%v %q %v", err, body, resp)
	}
	if connects.Load() != 2 || withAuth.Load() != 2 || srv.Requests.Load() != 1 {
		t.Errorf("%d tunnels (%d with the proxy's credentials) and %d requests, want 2, 2 and 1", connects.Load(), withAuth.Load(), srv.Requests.Load())
	}
}
