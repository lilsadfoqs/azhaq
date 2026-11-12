package certfacts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func cert(t *testing.T, notAfter time.Time, names []string, ips ...net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cn.test"}, DNSNames: names, IPAddresses: ips,
		NotBefore: notAfter.Add(-24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOfJudgesTheNameAsked(t *testing.T) {
	now := time.Now()
	c := cert(t, now.Add(time.Hour), []string{"a.test", "*.wild.test"}, net.ParseIP("10.0.0.1"))
	for _, tc := range []struct {
		host     string
		mismatch bool
		asked    string
	}{
		{"a.test", false, "a.test"},
		{"A.TEST", false, "A.TEST"},
		{"x.wild.test", false, "x.wild.test"},
		{"x.y.wild.test", true, "x.y.wild.test"},
		{"b.test", true, "b.test"},
		{"cn.test", false, "cn.test"}, // the common name counts
		{"10.0.0.1", false, ""},       // an address is not judged
		{"", false, ""},
	} {
		f := Of(c, tc.host, now)
		if f.Mismatch != tc.mismatch || f.Asked != tc.asked {
			t.Errorf("%q: mismatch %v asked %q, want %v %q", tc.host, f.Mismatch, f.Asked, tc.mismatch, tc.asked)
		}
	}
	f := Of(c, "a.test", now)
	if f.Subject != "CN=cn.test" || len(f.SANs) != 3 || f.SANs[2] != "10.0.0.1" || !f.SelfSigned || f.Expired {
		t.Errorf("%+v", f)
	}
	if !Of(c, "a.test", now.Add(2*time.Hour)).Expired {
		t.Error("a certificate past its end is not expired")
	}
}
