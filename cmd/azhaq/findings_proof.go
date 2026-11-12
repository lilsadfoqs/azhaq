package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/takeover"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// tierCounts is how many rows each tier holds. Every row of the findings
// output is in exactly one tier, so the three add up to the rows.
type tierCounts struct {
	Findings        int `json:"findings"`
	Identifications int `json:"identifications"`
	Leads           int `json:"leads"`
}

func (c tierCounts) String() string {
	return fmt.Sprintf("%s, %s, %s", plural(c.Findings, "finding"), plural(c.Identifications, "identification"), plural(c.Leads, "lead"))
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// hostPort splits the host and port a URL names.
func hostPort(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0
	}
	port := 0
	if p, err := strconv.Atoi(u.Port()); err == nil {
		port = p
	}
	return u.Hostname(), port
}

// speaksFirst names the services that send a greeting on connect, so that
// nothing needs to be sent to read what identifies them.
var speaksFirst = map[string]bool{
	"ssh": true, "ftp": true, "smtp": true, "pop3": true, "imap": true, "mysql": true, "telnet": true,
	"vnc": true, "irc": true, "nntp": true, "sieve": true, "icy": true, "ftp-or-smtp": true,
}

// identProof is the proof of a product and version a service named: the
// answer the stage received, the request that got it, and the command that
// shows it again.
func identProof(svc advisory.Service) *proof.Proof {
	host := svc.Host
	if host == "" {
		host = svc.IP
	}
	excerpt := proof.Printable([]byte(svc.Banner), proof.MaxExcerpt)
	if excerpt == "" {
		excerpt = strings.TrimSpace(svc.Product + " " + svc.Version)
	}
	p := &proof.Proof{ObservedAt: stamp(svc.ObservedAt), Excerpt: excerpt}
	switch {
	case svc.From != "" || svc.Origin != "":
		target := svc.From
		how := "azhaq-http"
		if target == "" {
			target, how = svc.Origin+"/", "azhaq-ports"
		}
		p.Method, p.Target, p.ExcerptPart, p.How, p.Reproduce = "GET", target, "header", how, proof.Curl("GET", target)
		if svc.From == "" && !strings.HasPrefix(excerpt, "Server") {
			p.ExcerptPart = "banner"
		}
	default:
		var req []byte
		if !speaksFirst[svc.Service] {
			req = verify.RequestFor(svc)
		}
		p.Method, p.Target, p.ExcerptPart, p.How = "connect", svc.Target(), "banner", "azhaq-ports"
		if len(req) > 0 {
			p.Method, p.ExcerptPart, p.RequestBytes = "send", "response", proof.EscapeBytes(req)
		}
		switch {
		case svc.TLS:
			p.Reproduce = proof.OpenSSL(host, svc.Port, req)
		case svc.Proto == "udp":
			p.Reproduce = strings.Replace(proof.NC(host, svc.Port, req), "nc -w 3", "nc -u -w 3", 1)
		default:
			p.Reproduce = proof.NC(host, svc.Port, req)
		}
	}
	return p
}

// servicesByTarget are the services the run named, by host:port and product,
// to give an identification the answer it was read from.
func servicesByTarget(obs []types.StoredObservation) map[string]advisory.Service {
	out := map[string]advisory.Service{}
	for _, list := range [][]advisory.Service{advisory.ServicesAnyVersion(obs), advisory.Services(obs)} {
		for _, s := range list {
			k := s.Target() + "\x00" + advisory.ProductKey(s.Product)
			if _, ok := out[k]; !ok || s.Version != "" {
				out[k] = s
			}
		}
	}
	return out
}

// pathRecord is the record of a path check's verdict: a finding with its
// proof, or a lead with the check that would prove it. A dropped answer has
// none.
func pathRecord(v proof.Verdict, command string) (findingRecord, bool) {
	if v.Dropped() || v.Tier == "" {
		return findingRecord{}, false
	}
	host, port := hostPort(v.URL)
	rec := findingRecord{Kind: v.Kind, Severity: v.Severity, Host: host, Port: port, URL: v.URL, Command: command,
		Request: "GET " + v.URL, Collector: "azhaq-paths"}
	if v.Tier == proof.TierFinding && v.Proof.Complete() {
		rec.Tier, rec.Label, rec.Proof = proof.TierFinding, "proved", v.Proof
		rec.Evidence = fmt.Sprintf("HTTP %d %s, %s: %s", v.Status, v.Proof.ContentType, v.What, v.Proof.Excerpt)
		rec.Collector = v.Proof.How
		return rec, true
	}
	rec.Tier, rec.Label, rec.Severity = proof.TierLead, "lead", "info"
	rec.Evidence = v.What + " named by its path; " + v.Reason
	rec.Check = v.Check
	return rec, true
}

// traceRecordProof is the proof of a stack trace in an answer.
func traceProof(url, via string, status int, observed time.Time, excerpt string, offset *int, ct string) *proof.Proof {
	part := "body"
	if excerpt == "" {
		excerpt = "(the exception line)"
	}
	return &proof.Proof{ObservedAt: stamp(observed), Method: "GET", Target: url, Status: status, ContentType: ct, Excerpt: excerpt,
		ExcerptPart: part, ExcerptOffset: offset, How: via, Reproduce: proof.Curl("GET", url)}
}

// secretRecord is the record of a credential a script carried: a finding
// when its own format names it (a key with a known shape, not a guess from
// the name it was assigned to), a lead otherwise. The value is never in it.
func secretRecord(s secretRow, command string) findingRecord {
	host, port := hostPort(s.Where)
	rec := findingRecord{Kind: "secret", Severity: s.Severity, Host: host, Port: port, URL: s.Where, Command: command,
		Request: "GET " + s.Where, Product: s.Kind, Collector: "azhaq-js"}
	if s.Severity == "" {
		rec.Severity = "info"
	}
	excerpt := s.Context
	if excerpt == "" {
		excerpt = strings.TrimSpace(s.Name + " = " + s.Redacted)
	}
	grep := s.Value
	if len(grep) > 12 {
		grep = grep[:6]
	} else if s.Name != "" {
		grep = s.Name
	} else if len(grep) > 4 {
		grep = grep[:4]
	}
	p := &proof.Proof{ObservedAt: stamp(s.Observed), Method: "GET", Target: s.Where, Status: 200, Excerpt: excerpt,
		ExcerptPart: "body", ExcerptOffset: s.Offset, How: "azhaq-js",
		Reproduce: proof.Curl("GET", s.Where) + " | grep -a -F -o -- " + proof.Quote(grep)}
	// Without -i the body alone is what grep reads: the same excerpt.
	p.Reproduce = strings.Replace(p.Reproduce, "curl -sS -i", "curl -sS", 1)
	known := s.Rule == "known key format" && s.Severity != "info"
	switch {
	case known && p.Complete():
		rec.Tier, rec.Label, rec.Proof = proof.TierFinding, "proved", p
		rec.Evidence = fmt.Sprintf("%s in %s: %s", s.Kind, s.Where, excerpt)
	default:
		rec.Tier, rec.Label, rec.Severity = proof.TierLead, "lead", "info"
		rec.Evidence = fmt.Sprintf("%s in %s, listed by %q: %s", s.Kind, s.Where, s.Rule, excerpt)
		rec.Check = "check the value with the service that issued it (azhaq does not try a credential); the match: " + p.Reproduce
	}
	return rec
}

// takeoverRecord is the record of a name another party may claim: a finding
// when the service itself answered with its page for an unclaimed name, a
// lead when the name only does not resolve.
func takeoverRecord(t takeoverRow, command string) findingRecord {
	rec := findingRecord{Kind: "takeover", Severity: "high", Host: t.Host, Product: t.Service, Command: command, Collector: "azhaq-http",
		Request: "GET http://" + t.Host + "/"}
	f := t.Settled()
	dig := "dig +short CNAME " + proof.Quote(t.Host)
	if f.Status == takeover.Verified {
		target := "http://" + t.Host + "/"
		p := &proof.Proof{ObservedAt: stamp(t.at), Method: "GET", Target: target, Excerpt: proof.Printable([]byte(f.Evidence), proof.MaxExcerpt),
			ExcerptPart: "body", How: "azhaq-http", Reproduce: dig + " && " + proof.Curl("GET", target)}
		if p.Complete() {
			rec.Tier, rec.Label, rec.Proof = proof.TierFinding, "proved", p
			rec.Evidence = f.Evidence
			return rec
		}
	}
	rec.Tier, rec.Label, rec.Severity = proof.TierLead, "lead", "info"
	rec.Evidence = f.Evidence
	rec.Check = "claim the name at " + f.Service + " (azhaq does not): " + dig + " names the target"
	return rec
}
