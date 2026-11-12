// Package certfacts reads what a server's certificate states about itself
// from a handshake already made: no request of its own.
package certfacts

import (
	"bytes"
	"crypto/x509"
	"net"
	"strings"
	"time"
)

// Facts are a leaf certificate's facts, judged for the host that was asked.
type Facts struct {
	Subject    string   `json:"subject"`
	SANs       []string `json:"sans,omitempty"` // DNS names, then addresses
	Issuer     string   `json:"issuer"`
	NotBefore  string   `json:"not_before"` // RFC 3339, UTC
	NotAfter   string   `json:"not_after"`
	SelfSigned bool     `json:"self_signed,omitempty"`
	Expired    bool     `json:"expired,omitempty"`
	Mismatch   bool     `json:"name_mismatch,omitempty"`
	// Asked is the name the mismatch was judged against. It is empty when the
	// host asked was an address: a certificate rarely names one.
	Asked string `json:"asked,omitempty"`
}

// Of reads c as it stands at now. host is the name the connection asked for.
func Of(c *x509.Certificate, host string, now time.Time) Facts {
	f := Facts{
		Subject:    c.Subject.String(),
		Issuer:     c.Issuer.String(),
		NotBefore:  c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   c.NotAfter.UTC().Format(time.RFC3339),
		SelfSigned: SelfSigned(c),
		Expired:    now.After(c.NotAfter),
	}
	f.SANs = append(f.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		f.SANs = append(f.SANs, ip.String())
	}
	if host != "" && net.ParseIP(strings.Trim(host, "[]")) == nil {
		f.Asked = host
		f.Mismatch = Mismatched(host, Names(c))
	}
	return f
}

// Names are the names a certificate answers to: its DNS names and, as a
// browser once did, its common name.
func Names(c *x509.Certificate) []string {
	return append(append([]string(nil), c.DNSNames...), c.Subject.CommonName)
}

// SelfSigned: the certificate has no authority key id, or one that is its own
// key id, as httpx reads it.
func SelfSigned(c *x509.Certificate) bool {
	return len(c.AuthorityKeyId) == 0 || bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId)
}

// Mismatched: none of names is host (a wildcard covers one label).
func Mismatched(host string, names []string) bool {
	if host == "" {
		return false
	}
	host = strings.ToLower(host)
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return false
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if _, tail, ok := strings.Cut(host, "."); ok && tail == rest {
				return false
			}
		}
	}
	return true
}
