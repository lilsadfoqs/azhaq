package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// CASigned is a server certificate for names, valid from notBefore to
// notAfter, signed by a test CA: it has the authority key id a signed
// certificate has, and the subject CN "leaf" (the issuer is "Test CA").
func CASigned(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	ca, caKey := cert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	leaf, key := cert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}, ca, caKey)
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
}

// SelfSigned is a server certificate that signed itself, for names, valid
// from notBefore to notAfter (subject and issuer CN "self").
func SelfSigned(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	c, key := cert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "self"}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}, nil, nil)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key}
}

func cert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
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
