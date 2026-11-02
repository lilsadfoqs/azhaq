package engine

import (
	"encoding/json"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// A source that fails while others answered for the domain is partial —
// crt.sh included: a transient crt.sh blip does not make the exit code 3
// when the other sources returned the names. (`-fail-on-errors` still
// treats every failure as exit 3.)
func TestMarkPartialWhenOthersAnswered(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"domain": "a.test", "sources": map[string]any{
		"crtsh": map[string]any{"error": "timeout"}, "anubis": map[string]any{"error": "HTTP 502"}, "certspotter": map[string]any{"count": 5.0}}})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-subdomains", Payload: payload}}}
	fs := []Failure{
		{Collector: "azhaq-subdomains", Source: "crtsh", Error: "timeout", Targets: []string{"a.test"}},
		{Collector: "azhaq-subdomains", Source: "anubis", Error: "HTTP 502", Targets: []string{"a.test"}},
	}
	got := MarkPartial(fs, nil, obs)
	if !got[0].Partial || !got[1].Partial {
		t.Errorf("both should be partial (certspotter answered): crtsh %v, anubis %v", got[0].Partial, got[1].Partial)
	}
}

// When no source answered for the domain, a failure is not partial: the
// results are missing, and the run exits 3.
func TestMarkPartialNoneAnswered(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"domain": "a.test", "sources": map[string]any{
		"crtsh": map[string]any{"error": "timeout"}, "anubis": map[string]any{"error": "HTTP 502"}}})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-subdomains", Payload: payload}}}
	fs := []Failure{{Collector: "azhaq-subdomains", Source: "crtsh", Error: "timeout", Targets: []string{"a.test"}}}
	got := MarkPartial(fs, nil, obs)
	if got[0].Partial {
		t.Error("no source answered, so the failure is not partial")
	}
}

// An archive that kept failing keeps its tries and the server's words as
// its reason, and is retryable when the words are a 429, a 5xx or a drop.
func TestShortErrorKeepsTheTriesOfAnArchive(t *testing.T) {
	for raw, retry := range map[string]bool{
		"failed after 4 tries, 429 Too Many Requests":                                 true,
		"failed after 4 tries, 503 Service Unavailable, Retry-After 1m0s (waited 3s)": true,
		"failed after 4 tries, dial tcp 127.0.0.1:9: connect: connection refused":     false,
		"failed after 4 tries, read tcp 10.0.0.1:5->1.2.3.4:443: i/o timeout":         true,
		"failed after 1 try, 429 Too Many Requests; 3 pages were read before":         true,
	} {
		if got := ShortError(raw); got != raw {
			t.Errorf("%q shortened to %q", raw, got)
		}
		if Retryable(raw) != retry {
			t.Errorf("%q: retryable %v", raw, !retry)
		}
	}
}

// A TLS failure keeps what the handshake said: the alert, the version or the
// certificate's fault, not a bare "TLS error"; none of them is retried.
func TestShortErrorKeepsTheTLSReason(t *testing.T) {
	for raw, want := range map[string]string{
		`Get "https://h/": remote error: tls: handshake failure`: "TLS error: remote error: tls: handshake failure",
		`Get "https://h/": remote error: tls: protocol version not supported; fallback TLS client: remote error: tls: protocol version not supported`: "TLS error: remote error: tls: protocol version not supported",
		`Get "https://h/": tls: no supported versions satisfy MinVersion and MaxVersion`:                                                              "TLS error: tls: no supported versions satisfy MinVersion and MaxVersion",
		`Get "https://h/": tls: failed to verify certificate: x509: certificate has expired or is not yet valid`:                                      "TLS error: tls: failed to verify certificate: x509: certificate has expired or is not yet valid",
		`x509: certificate signed by unknown authority`:                                                                                               "TLS error: x509: certificate signed by unknown authority",
	} {
		if got := ShortError(raw); got != want {
			t.Errorf("%q: got %q, want %q", raw, got, want)
		}
		if Retryable(raw) {
			t.Errorf("%q is retryable", raw)
		}
	}
}
