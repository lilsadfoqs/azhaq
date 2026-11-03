package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// Without -live every name the sources gave is printed, each marked as a
// candidate: nothing is confirmed, so no row says dns, and the summary does
// not count a candidate as DNS-confirmed.
func TestSubsTiersCandidatesAreNeverConfirmed(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "api.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Names: []string{"guess1.example.org", "guess2.example.org", "www.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	var hosts []string
	for _, r := range jsonRows(t, out) {
		hosts = append(hosts, r["host"].(string))
		if r["tier"] != "candidate" {
			t.Errorf("%v: tier %v, want candidate", r["host"], r["tier"])
		}
		if len(r["sources"].([]any)) == 0 {
			t.Errorf("%v: a candidate names its sources", r["host"])
		}
	}
	slices.Sort(hosts)
	if want := []string{"api.example.org", "guess1.example.org", "guess2.example.org", "www.example.org"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("printed %v, want %v", hosts, want)
	}
	c := rep.Counts
	if c["raw candidates"] != 4 {
		t.Errorf("raw candidates %d: %v", c["raw candidates"], c)
	}
	if _, ok := c["DNS-confirmed"]; ok {
		t.Errorf("DNS-confirmed counted with no lookup: %v", c)
	}
	var tiers, cov bool
	for _, n := range rep.Notes {
		tiers = tiers || strings.HasPrefix(n, "tiers: 4 raw candidates") && strings.Contains(n, "DNS-confirmed not asked (-live)")
		cov = cov || strings.HasPrefix(n, "coverage (raw candidates): ")
		if strings.HasPrefix(n, "coverage (DNS-confirmed)") {
			t.Errorf("a coverage for a tier nothing reached: %q", n)
		}
	}
	if !tiers || !cov {
		t.Errorf("notes %q", rep.Notes)
	}
}

// With -live the printed rows are the DNS-confirmed tier and the candidates
// that did not resolve are counted apart, never printed as results.
func TestSubsTiersLiveSeparatesRawFromConfirmed(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a: map[string]string{"www.example.org": "192.0.2.10", "real.example.org": "192.0.2.12"},
	})
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "stale.example.org"}},
		subcol.TestSource{Name: "t", Default: true, Names: []string{"www.example.org", "old.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Names: []string{"real.example.org", "junk1.example.org", "junk2.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	var hosts []string
	for _, r := range jsonRows(t, out) {
		hosts = append(hosts, r["host"].(string))
		if r["tier"] != "dns" {
			t.Errorf("%v: tier %v, want dns", r["host"], r["tier"])
		}
	}
	slices.Sort(hosts)
	if want := []string{"real.example.org", "www.example.org"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("printed %v, want %v", hosts, want)
	}
	c := rep.Counts
	if c["raw candidates"] != 6 || c["DNS-confirmed"] != 2 || c["did not resolve"] != 4 {
		t.Errorf("counts %v", c)
	}
	if c["raw candidates"]-c["did not resolve"] != c["DNS-confirmed"] {
		t.Errorf("raw less what did not resolve is not the DNS-confirmed: %v", c)
	}
	var tiers, cov bool
	for _, n := range rep.Notes {
		tiers = tiers || strings.HasPrefix(n, "tiers: 6 raw candidates") && strings.Contains(n, "2 DNS-confirmed")
		cov = cov || strings.HasPrefix(n, "coverage (DNS-confirmed): ")
	}
	if !tiers || !cov {
		t.Errorf("notes %q", rep.Notes)
	}
}

// A source that fails after giving names, or at all, makes the summary
// degraded and counted in failures, with exit 0 while another answered; the
// names the others gave are still printed.
func TestSubsFailedSourceDegradesTheSummaryNotTheResult(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "good", Default: true, Names: []string{"www.example.org", "api.example.org"}},
		subcol.TestSource{Name: "bad", Default: true, Err: errors.New("HTTP 504")},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-no-history")
	if code != exitOK || rep.Failures != 1 {
		t.Fatalf("exit %d, want %d with 1 failure: %+v", code, exitOK, rep)
	}
	if got := len(jsonRows(t, out)); got != 2 {
		t.Errorf("%d names printed, want 2:\n%s", got, out)
	}
	if !rep.Degraded || rep.Counts["sources failed"] != 1 || len(rep.DegradedBy) != 1 || rep.DegradedBy[0].Source != "bad" {
		t.Errorf("degraded %v by %+v counts %v", rep.Degraded, rep.DegradedBy, rep.Counts)
	}
}

// -http asks each live name's web service one request: the names that
// answered are the HTTP-confirmed tier, the others stay DNS-confirmed, and
// no candidate is counted in either.
func TestSubsTiersHTTPConfirmsOnlyWhatAnswered(t *testing.T) {
	t.Chdir(t.TempDir())
	// A proxy for every request: www.example.org gets a page, any other name
	// gets a closed connection, as a host with nothing listening does.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || !strings.HasPrefix(r.Host, "www.example.org") {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>www</title>"))
	}))
	t.Cleanup(proxy.Close)
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.10", "mail.example.org": "192.0.2.11"}})
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "mail.example.org", "stale.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-http", "-web-ports", "80", "-http-proxy", proxy.URL, "-resolvers", resolvers, "-no-history")
	tier := map[string]any{}
	for _, r := range jsonRows(t, out) {
		tier[r["host"].(string)] = r["tier"]
	}
	if want := map[string]any{"www.example.org": "http", "mail.example.org": "dns"}; !reflect.DeepEqual(tier, want) {
		t.Errorf("tiers %v, want %v (exit %d)", tier, want, code)
	}
	c := rep.Counts
	if c["raw candidates"] != 3 || c["DNS-confirmed"] != 2 || c["HTTP-confirmed"] != 1 {
		t.Errorf("counts %v", c)
	}
}
