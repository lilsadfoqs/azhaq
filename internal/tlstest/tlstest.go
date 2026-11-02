// Package tlstest serves HTTPS the way crypto/tls cannot: TLS 1.2 with RSA
// key exchange or DHE only, which is what the fallback client of
// internal/egress exists for. Tests use it; no command does.
package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	zrsa "github.com/zmap/zcrypto/rsa"
	ztls "github.com/zmap/zcrypto/tls"
)

// Suites a server can be limited to.
const (
	RSAGCM  = ztls.TLS_RSA_WITH_AES_128_GCM_SHA256
	RSACBC  = ztls.TLS_RSA_WITH_AES_128_CBC_SHA
	DHEGCM  = ztls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	DHECBC  = ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	Reply   = "hello from a legacy server"
	VersTLS = ztls.VersionTLS12
)

// Server is a listener whose handshakes and requests it counts.
type Server struct {
	Addr string
	// Conns are the connections accepted, Handshakes those that completed one,
	// Requests the HTTP requests read.
	Conns, Handshakes, Requests atomic.Int32
}

// Serve answers each request over HTTPS with 200 and Reply (the body of a
// POST is read and its length added in the X-Body header). Its TLS versions
// run from min to max (0: TLS 1.2 only), its suites are those given.
func Serve(t *testing.T, min, max uint16, suites ...uint16) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "legacy.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"legacy.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	zkey := &zrsa.PrivateKey{PublicKey: zrsa.PublicKey{N: key.N, E: big.NewInt(int64(key.E))}, D: key.D, Primes: key.Primes}
	zkey.Precompute()
	if min == 0 {
		min = ztls.VersionTLS12
	}
	if max == 0 {
		max = ztls.VersionTLS12
	}
	ln, err := ztls.Listen("tcp", "127.0.0.1:0", &ztls.Config{
		Certificates: []ztls.Certificate{{Certificate: [][]byte{der}, PrivateKey: zkey}},
		CipherSuites: suites, MinVersion: min, MaxVersion: max,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{Addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.Conns.Add(1)
			go s.serve(c.(*ztls.Conn))
		}
	}()
	return s
}

func (s *Server) serve(c *ztls.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if c.Handshake() != nil {
		return
	}
	s.Handshakes.Add(1)
	var buf []byte
	tmp := make([]byte, 4096)
	for !strings.Contains(string(buf), "\r\n\r\n") {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return
		}
	}
	s.Requests.Add(1)
	head, body, _ := strings.Cut(string(buf), "\r\n\r\n")
	n := len(body)
	for _, l := range strings.Split(head, "\r\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "content-length") {
			want, _ := strconv.Atoi(strings.TrimSpace(v))
			for n < want {
				m, err := c.Read(tmp)
				n += m
				if err != nil {
					break
				}
			}
		}
	}
	io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(Reply))+"\r\nX-Body: "+strconv.Itoa(n)+"\r\nConnection: close\r\n\r\n"+Reply)
}
