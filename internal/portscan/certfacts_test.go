package portscan

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// pki makes a CA and a leaf it signs for names, valid from notBefore to
// notAfter, as a server's certificate. The leaf has the authority key id a
// signed certificate has.
func pki(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	ca, caKey := certOf(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	leaf, key := certOf(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}, ca, caKey)
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
}

// selfSigned makes a certificate that signed itself, for names.
func selfSigned(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	c, key := certOf(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "self"}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}, nil, nil)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key}
}

func certOf(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// tlsPort serves cert on a loopback port that answers a request with a 200.
func tlsPort(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
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
			go func() {
				defer c.Close()
				if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
					c.Write([]byte("HTTP/1.0 200 OK\r\nServer: certtest\r\n\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func scanAs(t *testing.T, host string, port int) Open {
	t.Helper()
	s := &Scanner{Banner: 150 * time.Millisecond, Timeout: time.Second}
	r, err := s.ScanEach(context.Background(), host, "127.0.0.1", []int{port})
	if err != nil || len(r.Open) != 1 {
		t.Fatalf("scan: %v %+v", err, r)
	}
	return r.Open[0]
}

// A TLS service gets the facts of the certificate its handshake showed:
// the subject, names, issuer and dates, and whether it is expired,
// self-signed or not for the name asked. The scan opens no connection for it.
func TestTLSServiceGetsCertificateFacts(t *testing.T) {
	now := time.Now()
	good := tlsPort(t, pki(t, now.Add(-time.Hour), now.Add(24*time.Hour), "svc.test"))
	o := scanAs(t, "svc.test", good)
	c := o.Cert
	if !o.TLS || c == nil {
		t.Fatalf("a TLS service has no certificate facts: %+v", o)
	}
	if c.Subject != "CN=leaf" || c.Issuer != "CN=Test CA" || len(c.SANs) != 1 || c.SANs[0] != "svc.test" || c.NotBefore == "" || c.NotAfter == "" {
		t.Errorf("facts: %+v", c)
	}
	if c.Expired || c.SelfSigned || c.Mismatch || c.Asked != "svc.test" {
		t.Errorf("a valid certificate signed by a CA for the name asked has flags: %+v", c)
	}
	// The same handshake is judged for another name: the only change is the mismatch.
	if o := scanAs(t, "other.test", good); o.Cert == nil || !o.Cert.Mismatch || o.Cert.Expired || o.Cert.SelfSigned || o.Cert.Asked != "other.test" {
		t.Errorf("a certificate for svc.test, asked as other.test: %+v", o.Cert)
	}
	// An address asked has no name to judge: no mismatch is claimed.
	if o := scanAs(t, "127.0.0.1", good); o.Cert == nil || o.Cert.Mismatch || o.Cert.Asked != "" {
		t.Errorf("an address asked: %+v", o.Cert)
	}

	expired := tlsPort(t, selfSigned(t, now.Add(-72*time.Hour), now.Add(-time.Hour), "old.test"))
	if o := scanAs(t, "old.test", expired); o.Cert == nil || !o.Cert.Expired || !o.Cert.SelfSigned || o.Cert.Mismatch {
		t.Errorf("an expired self-signed certificate for the name asked: %+v", o.Cert)
	}
}

// The facts are read from the handshake the identification already made:
// httptest's own certificate is self-signed and names example.com.
func TestHTTPTestServerCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	if o := scanAs(t, "example.com", port); o.Service != "https" || o.Cert == nil || !o.Cert.SelfSigned || o.Cert.Expired || o.Cert.Mismatch {
		t.Errorf("example.com: %+v %+v", o, o.Cert)
	}
	if o := scanAs(t, "localhost", port); o.Cert == nil || !o.Cert.Mismatch || o.Cert.Asked != "localhost" {
		t.Errorf("localhost is not a name its certificate holds: %+v", o.Cert)
	}
}

// A port that speaks no TLS has no certificate facts.
func TestPlainServiceHasNoCertificate(t *testing.T) {
	ssh := listen(t, func(c net.Conn) { c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")) })
	if o := scanOne(t, ssh); o.Cert != nil || o.TLS {
		t.Errorf("%+v", o)
	}
}
