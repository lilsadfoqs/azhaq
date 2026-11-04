package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// A front page that is a hosting service's page for a name nobody claimed
// is a takeover candidate in the summary.
func TestTakeoverInSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`<html><body><p><strong>There isn't a GitHub Pages site here.</strong></p></body></html>`))
	}))
	defer srv.Close()
	_, errOut, _ := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-depth", "0"})
	})
	var sum struct {
		Takeover []struct{ Host, Service, Strength, Evidence string }
	}
	line := errOut[strings.LastIndex(strings.TrimSpace(errOut), "\n")+1:]
	if err := json.Unmarshal([]byte(line), &sum); err != nil || len(sum.Takeover) != 1 || sum.Takeover[0].Service != "GitHub Pages" || sum.Takeover[0].Host != "127.0.0.1" {
		t.Fatalf("summary %s (%v)", errOut, err)
	}
}

// A service's page is judged again by where DNS says the name points.
func TestTakeoverPageAndCNAME(t *testing.T) {
	page := func(host string) types.StoredObservation {
		raw, _ := json.Marshal(map[string]any{"url": "https://" + host + "/", "takeover": map[string]any{"service": "GitHub Pages", "strength": "page",
			"evidence": `GitHub Pages's page for a name nobody claimed: "There isn't a GitHub Pages site here." (no CNAME known: check where the name points)`}})
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-http", Payload: raw}}
	}
	dns := func(host string, cnames ...string) types.StoredObservation {
		raw, _ := json.Marshal(map[string]any{"fqdn": host, "cnames": cnames})
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-dns", Payload: raw}}
	}
	got := takeovers(nil, []types.StoredObservation{
		page("a.example.com"), dns("a.example.com", "acme.github.io"), // to the service: strong
		page("b.example.com"), dns("b.example.com", "lb.example.net"), // elsewhere: nothing
		page("c.example.com"), // no CNAME known: the page alone
	})
	if len(got) != 2 || got[0].Host != "a.example.com" || got[0].Strength != "strong" || got[0].Target != "acme.github.io" ||
		got[1].Host != "c.example.com" || got[1].Strength != "page" {
		t.Errorf("%+v", got)
	}
}

// The summary counts candidates and verified apart, and each is what its row
// says: a CNAME to a name that did not resolve is a candidate whatever the
// provider; the provider's own page beside a CNAME to it is verified.
func TestTakeoverSummaryCountsCandidatesAndVerified(t *testing.T) {
	page := func(host string) types.StoredObservation {
		raw, _ := json.Marshal(map[string]any{"url": "https://" + host + "/", "takeover": map[string]any{"service": "GitHub Pages", "strength": "page",
			"evidence": `GitHub Pages's page for a name nobody claimed: "There isn't a GitHub Pages site here."`}})
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-http", Payload: raw}}
	}
	dnsObs := func(host string, f map[string]any, cnames ...string) types.StoredObservation {
		p := map[string]any{"fqdn": host, "cnames": cnames}
		if f != nil {
			p["takeover"] = f
		}
		raw, _ := json.Marshal(p)
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-dns", Payload: raw}}
	}
	dangling := map[string]any{"service": "Azure", "target": "gone.azurewebsites.net", "strength": "dangling", "status": "candidate", "evidence": "observed: CNAME to gone.azurewebsites.net"}
	rep := newReport("run")
	rep.Takeover = takeovers(nil, []types.StoredObservation{
		page("a.example.com"), dnsObs("a.example.com", nil, "acme.github.io"), // the service's page beside a CNAME to it
		dnsObs("b.example.com", dangling, "gone.azurewebsites.net"),
		page("c.example.com"), // a page, no CNAME known
	})
	rep.settle()
	if rep.TakeoverVerified != 1 || rep.TakeoverCandidates != 2 || len(rep.Takeover) != 3 {
		t.Fatalf("verified %d, candidates %d, rows %d", rep.TakeoverVerified, rep.TakeoverCandidates, len(rep.Takeover))
	}
	status := map[string]string{}
	for _, r := range rep.Takeover {
		status[r.Host] = r.Status
	}
	if status["a.example.com"] != "verified" || status["b.example.com"] != "candidate" || status["c.example.com"] != "candidate" {
		t.Errorf("statuses %v", status)
	}
	raw, _ := json.Marshal(rep)
	var back struct {
		Candidates int `json:"takeover_candidates"`
		Verified   int `json:"takeover_verified"`
	}
	if json.Unmarshal(raw, &back) != nil || back.Candidates != 2 || back.Verified != 1 {
		t.Errorf("the summary JSON: %s", raw)
	}
	var b strings.Builder
	rep.print(&b)
	for _, want := range []string{"! takeover verified (strong): a.example.com", "! takeover candidate (dangling): b.example.com", "! takeover candidate (page): c.example.com"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the text summary lacks %q:\n%s", want, b.String())
		}
	}
	// A summary with none says no count.
	empty := newReport("run")
	empty.settle()
	if raw, _ := json.Marshal(empty); strings.Contains(string(raw), "takeover_") {
		t.Errorf("counts with no takeover: %s", raw)
	}
}
