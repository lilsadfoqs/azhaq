package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/certfacts"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/types"
)

// certLeads are the leads for the TLS services a port scan found whose
// certificate, as the handshake presented it, is expired, self-signed or not
// for the name asked. The scan read the facts and sent nothing more, and a
// certificate says nothing of whether the service is weak: each is a lead
// with the command that shows the certificate again. Of a service scanned
// twice the newest scan stands.
func certLeads(obs []types.StoredObservation, command string) []findingRecord {
	type seen struct {
		at   string
		rec  findingRecord
		have bool
	}
	newest := map[string]seen{}
	var order []string
	for _, o := range obs {
		if o.Collector != "azhaq-ports" || o.Kind != "ports" {
			continue
		}
		var p struct {
			Host     string `json:"host"`
			IP       string `json:"ip"`
			Range    bool   `json:"range"`
			Services []struct {
				Port int              `json:"port"`
				Cert *certfacts.Facts `json:"certificate"`
			} `json:"services"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Range {
			continue
		}
		host := p.Host
		if host == "" {
			host = p.IP
		}
		for _, s := range p.Services {
			if s.Cert == nil {
				continue
			}
			key := host + ":" + strconv.Itoa(s.Port)
			at := o.ObservedAt.UTC().Format("2006-01-02T15:04:05.000000000Z")
			old, ok := newest[key]
			if ok && old.at > at {
				continue
			}
			if !ok {
				order = append(order, key)
			}
			rec, have := certRecord(host, s.Port, *s.Cert, command)
			newest[key] = seen{at: at, rec: rec, have: have}
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

// certRecord is the lead of one certificate, when it has a fact to state.
func certRecord(host string, port int, c certfacts.Facts, command string) (findingRecord, bool) {
	var facts []string
	if c.Expired {
		facts = append(facts, "expired (not after "+c.NotAfter+")")
	}
	if c.SelfSigned {
		facts = append(facts, "self-signed (issuer "+c.Issuer+")")
	}
	if c.Mismatch {
		facts = append(facts, "not for the name asked, "+c.Asked+" (names: "+strings.Join(c.SANs, ", ")+"; subject "+c.Subject+")")
	}
	if len(facts) == 0 {
		return findingRecord{}, false
	}
	target := host + ":" + strconv.Itoa(port)
	return findingRecord{
		Tier: proof.TierLead, Kind: "tls-certificate", Label: "lead", Severity: "info", Host: host, Port: port,
		Evidence:  "the certificate of " + target + " is " + strings.Join(facts, "; ") + ", read from the handshake the port scan made",
		Command:   command,
		Collector: "azhaq-ports",
		Check:     "read the certificate again: " + proof.OpenSSL(host, port, nil) + " | openssl x509 -noout -subject -issuer -dates -ext subjectAltName",
	}, true
}
