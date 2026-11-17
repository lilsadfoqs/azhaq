package main

import (
	"bytes"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/certfacts"
	"github.com/lilsadfoqs/azhaq/internal/httprow"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/types"
)

// certKind is the kind of the finding for a TLS service whose certificate,
// as its handshake presented it, is expired, self-signed or not for the name
// asked: what was measured, nothing of whether the service is weak.
const certKind = "tls-certificate"

// observedCertificate is its label: the facts are the handshake's own, so it
// is never labelled proved.
const observedCertificate = "observed-certificate"

// certRecords are the tls-certificate findings of a workspace, one per
// host and port, read from the handshake a stored row came from: the port
// scan's (azhaq-ports) or an HTTP answer's (azhaq-http). Nothing is asked
// again. Of a service seen twice the newest row stands, a renewed
// certificate included.
func certRecords(obs []types.StoredObservation, command string) []findingRecord {
	type seen struct {
		at   string
		rec  findingRecord
		have bool
	}
	newest := map[string]seen{}
	var order []string
	note := func(o types.StoredObservation, host string, port int, c certfacts.Facts, how string) {
		key := host + ":" + strconv.Itoa(port)
		at := o.ObservedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")
		old, ok := newest[key]
		if ok && old.at > at {
			return
		}
		if !ok {
			order = append(order, key)
		}
		rec, have := certRecord(host, port, c, stamp(o.ObservedAt), how, command)
		newest[key] = seen{at: at, rec: rec, have: have}
	}
	for _, o := range obs {
		switch {
		case o.Collector == "azhaq-ports" && o.Kind == "ports":
			p, err := portscan.ParseRow(o.Payload)
			if err != nil || p.Range {
				continue
			}
			host := p.Host
			if host == "" {
				host = p.IP
			}
			for _, s := range p.Services {
				if s.Cert != nil {
					note(o, host, s.Port, *s.Cert, "azhaq-ports")
				}
			}
		case o.Collector == "azhaq-http" && o.Kind == "application" && bytes.Contains(o.Payload, []byte(`"certificate"`)):
			row, err := httprow.ParseRow(o.Payload)
			if err != nil || row.Certificate == nil {
				continue
			}
			if host, port := httpsHostPort(row.URL); host != "" {
				note(o, host, port, *row.Certificate, "azhaq-http")
			}
		}
	}
	var out []findingRecord
	for _, k := range order {
		if s := newest[k]; s.have {
			out = append(out, s.rec)
		}
	}
	return out
}

// httpsHostPort is the host and port of an https URL, 443 when it names none.
func httpsHostPort(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", 0
	}
	port := 443
	if p, err := strconv.Atoi(u.Port()); err == nil {
		port = p
	}
	return u.Hostname(), port
}

// certRecord is the finding of one certificate, when it has a fact to state.
func certRecord(host string, port int, c certfacts.Facts, at, how, command string) (findingRecord, bool) {
	var facts []string
	if c.Expired {
		facts = append(facts, "expired (not after "+c.NotAfter+")")
	}
	if c.SelfSigned {
		facts = append(facts, "self-signed (subject "+c.Subject+", issuer "+c.Issuer+")")
	}
	if c.Mismatch {
		facts = append(facts, "not for the name asked, "+c.Asked+" (names: "+strings.Join(c.SANs, ", ")+"; subject "+c.Subject+")")
	}
	if len(facts) == 0 {
		return findingRecord{}, false
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	evidence := "observed: the certificate of " + target + " is " + strings.Join(facts, "; ") +
		", as its TLS handshake presented it. Whether the service is otherwise weak was not tested"
	excerpt := "subject " + c.Subject + "; issuer " + c.Issuer + "; not before " + c.NotBefore + "; not after " + c.NotAfter
	if len(c.SANs) > 0 {
		excerpt += "; names " + strings.Join(c.SANs, ", ")
	}
	p := &proof.Proof{ObservedAt: at, Method: "tls handshake", Target: target,
		Excerpt: proof.Printable([]byte(excerpt), proof.MaxExcerpt), ExcerptPart: "certificate",
		How: how, Reproduce: certReproduce(host, port)}
	return findingRecord{
		Tier: proof.TierFinding, Kind: certKind, Label: observedCertificate, Severity: "low", Host: host, Port: port,
		Request: "tls handshake " + target, Evidence: evidence, Command: command, Collector: how, Proof: p,
	}, true
}

// certReproduce shows the certificate again with no azhaq: the handshake, then
// the leaf's subject, issuer and dates. An address is not sent as a server name.
func certReproduce(host string, port int) string {
	cmd := "openssl s_client -connect " + net.JoinHostPort(host, strconv.Itoa(port))
	if net.ParseIP(host) == nil {
		cmd += " -servername " + proof.Quote(host)
	}
	return cmd + " </dev/null | openssl x509 -noout -subject -issuer -dates"
}
