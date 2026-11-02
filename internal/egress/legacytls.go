package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	ztls "github.com/zmap/zcrypto/tls"
)

// crypto/tls offers ECDHE and TLS 1.3 suites only: Go removed RSA key
// exchange and never had DHE, and no GODEBUG brings them back. A server that
// offers nothing else (a printer, an appliance, an old Java or OpenSSL
// config) answers the handshake with an alert, and curl -k still completes it.
// For those, and only after crypto/tls failed with an error such a server
// causes, a second connection runs the handshake with the TLS client of
// github.com/zmap/zcrypto (Apache-2.0 with BSD parts, a fork of crypto/tls
// that keeps those suites). The connection is made, held to the scope and the
// kill file and recorded like any other; nothing else uses the fork.

// legacySuites are what the fallback offers: ECDHE first, then DHE, then RSA
// key exchange, authenticated encryption before CBC.
var legacySuites = []uint16{
	ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, ztls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_RSA_WITH_AES_128_GCM_SHA256, ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, ztls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_RSA_WITH_AES_128_CBC_SHA256, ztls.TLS_RSA_WITH_AES_128_CBC_SHA, ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// LegacyTLSNeeded says err is what crypto/tls gets from a server that wants a
// handshake it does not offer: an alert for a ClientHello it cannot use (the
// handshake failure of no common suite, a version or a security level it will
// not accept, parameters or a message it dislikes), or a version or suite of
// the server's own that crypto/tls will not take. A timeout, a reset, an
// answer that is not TLS and a certificate are not this.
func LegacyTLSNeeded(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, m := range []string{
		"remote error: tls: handshake failure",
		"remote error: tls: protocol version not supported",
		"remote error: tls: insufficient security",
		"remote error: tls: illegal parameter",
		"remote error: tls: unexpected message",
		"remote error: tls: internal error",
		"tls: no supported versions satisfy MinVersion and MaxVersion",
		"tls: server selected unsupported protocol version",
		"tls: server chose an unconfigured cipher suite",
		"tls: failed to parse certificate from server",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// legacyConn is a connection the fallback client made. It reports its state
// as crypto/tls does, so every reader of a connection's version, suite and
// certificates reads it the same way.
type legacyConn struct {
	*ztls.Conn
	plain net.Conn
	state tls.ConnectionState
}

func (c *legacyConn) ConnectionState() tls.ConnectionState { return c.state }

// NetConn is the connection under the handshake, as crypto/tls's has it.
func (c *legacyConn) NetConn() net.Conn { return c.plain }

// legacyClient runs the handshake of cfg's server name and versions (from
// TLS 1.2 up, or its minimum below that, to 1.2) over conn. It refuses a
// config that verifies certificates: the fork is for observing a server that
// is taken as it is, as every handshake of azhaq does.
func legacyClient(ctx context.Context, conn net.Conn, cfg *tls.Config, host string) (*legacyConn, error) {
	if cfg == nil || !cfg.InsecureSkipVerify {
		return nil, errors.New("the fallback TLS client does not verify certificates")
	}
	name := cfg.ServerName
	if name == "" && net.ParseIP(host) == nil {
		name = host
	}
	zc := &ztls.Config{
		InsecureSkipVerify: true, ServerName: name, CipherSuites: legacySuites, ForceSuites: true, // the list as given: DHE is dropped from a hello otherwise
		MinVersion: ztls.VersionTLS12, MaxVersion: ztls.VersionTLS12,
	}
	if cfg.MinVersion != 0 && cfg.MinVersion < tls.VersionTLS12 {
		zc.MinVersion = cfg.MinVersion
	}
	tc := ztls.Client(conn, zc)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	zs := tc.ConnectionState()
	st := tls.ConnectionState{Version: zs.Version, HandshakeComplete: true, CipherSuite: zs.CipherSuite,
		ServerName: zs.ServerName, NegotiatedProtocol: zs.NegotiatedProtocol}
	for _, c := range zs.PeerCertificates {
		if x, err := x509.ParseCertificate(c.Raw); err == nil {
			st.PeerCertificates = append(st.PeerCertificates, x)
		}
	}
	return &legacyConn{Conn: tc, plain: conn, state: st}, nil
}

// CipherSuiteName is the name of a suite crypto/tls or the fallback client
// negotiated (crypto/tls knows no DHE suite, and shows its number only).
func CipherSuiteName(id uint16) string {
	if n := tls.CipherSuiteName(id); !strings.HasPrefix(n, "0x") {
		return n
	}
	if n, ok := dheNames[id]; ok {
		return n
	}
	return ztls.CipherSuiteName(id)
}

// dheNames are the DHE suites of RFC 5246 and 5288 (the fork has no names for them).
var dheNames = map[uint16]string{
	ztls.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:   "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	ztls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	ztls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	ztls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
}

// legacyProxyKey carries, in a request's context, the proxy its connection
// goes through, for the dial of the fallback transport (nil: direct).
type legacyProxyKey struct{}

// dialVia connects to addr through the proxy u: an HTTP proxy by CONNECT, a
// SOCKS5 one by its own handshake. The proxy is the user's, not a target.
func dialVia(ctx context.Context, u *url.URL, addr string) (net.Conn, error) {
	phost := u.Host
	if u.Port() == "" {
		phost = net.JoinHostPort(u.Hostname(), map[string]string{"http": "80", "socks5": "1080", "socks5h": "1080"}[u.Scheme])
	}
	switch u.Scheme {
	case "http":
		c, err := DialProxy(ctx, "tcp", phost)
		if err != nil {
			return nil, err
		}
		req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
		if u.User != nil {
			pw, _ := u.User.Password()
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)))
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		if err := req.Write(c); err != nil {
			c.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			c.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			c.Close()
			return nil, fmt.Errorf("the proxy answered CONNECT %s with %s", addr, resp.Status)
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", phost, auth, proxyDialer(DialProxy))
		if err != nil {
			return nil, err
		}
		return d.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	}
	return nil, fmt.Errorf("the fallback TLS client does not go through a %s proxy", u.Scheme)
}

// proxyDialer adapts the egress dial to what x/net/proxy forwards through.
type proxyDialer func(ctx context.Context, network, addr string) (net.Conn, error)

func (f proxyDialer) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}

func (f proxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}
