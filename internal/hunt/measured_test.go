package hunt

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/types"
)

// A dangling-dns row is a finding ranked by its severity with the other
// findings, before every lead: among forty leads, first of the list. A takeover
// lead for the same name stays a lead, after every finding and identification.
func TestDanglingDNSRanksWithTheFindings(t *testing.T) {
	var rows []engine.MapEntry
	for i := 0; i < 40; i++ {
		key := fmt.Sprintf("http://t.test/api/users/%d/orders", i)
		rows = append(rows, urlRow(key, "api", "visited", 200, nil))
	}
	p := &proof.Proof{ObservedAt: "2026-11-13T00:00:00Z", Method: "dns A", Target: "old.t.test", Excerpt: "old.t.test -> x.cloud.example; status: NXDOMAIN", ExcerptPart: "dns",
		How: "azhaq-dns", Reproduce: "dig @1.1.1.1 +noall +comments +answer A 'old.t.test'"}
	got := Build(Input{DB: "w.db", Rows: rows, Now: time.Now(), Since: 7 * 24 * time.Hour,
		Takeovers: []Takeover{{Host: "old.t.test", Dangling: true, Detail: "unverified: claim not attempted"}},
		Measured:  []Measured{{Kind: "dangling-dns", Host: "old.t.test", Severity: "low", Evidence: "x.cloud.example answered NXDOMAIN", Proof: p}}})
	var finding, lead *Row
	for i := range got {
		if got[i].Key == "old.t.test" && got[i].Tier == proof.TierFinding {
			finding = &got[i]
		}
		if got[i].Key == "old.t.test" && got[i].Tier == proof.TierLead {
			lead = &got[i]
		}
	}
	if finding == nil || finding.Rank > 3 || finding.Reasons[0].Signal != "dangling-dns" || finding.Next != p.Reproduce || finding.Proof == nil {
		t.Fatalf("finding %+v of %d rows", finding, len(got))
	}
	if lead == nil || lead.Rank <= finding.Rank || !has(lead, "takeover-candidate") || has(lead, "dangling-dns") {
		t.Errorf("the takeover lead stays a lead after it: %+v", lead)
	}
}

// A stack trace is a finding row of its own, a measured record: the route's
// 5xx lead does not repeat it, and a 5xx whose error text names a stack but
// has no record (fewer than three frames) is a lead, never a finding.
func TestTraceRecordIsOneFindingAndNoLead(t *testing.T) {
	row := func(path string) engine.MapEntry {
		return urlRow("http://t.test"+path, "api", "visited", 500, func(r *engine.MapEntry) { r.Title = "Error" })
	}
	payload, _ := json.Marshal(map[string]any{"url": "http://t.test/bare", "status": 500, "error_text": "stack", "error_sample": "Traceback (most recent call last)"})
	got := Build(Input{DB: "w.db", Now: time.Now(), Since: 7 * 24 * time.Hour,
		Rows:     []engine.MapEntry{row("/api"), row("/bare")},
		Obs:      []types.StoredObservation{{EntityID: "http://t.test/bare", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: payload}}},
		Measured: []Measured{{Kind: "error-disclosure", Type: "URL", Host: "http://t.test/api", Severity: "low", Evidence: "HTTP 500: boom (3 java frames)"}}})
	tiers := map[string]string{}
	for _, r := range got {
		if _, dup := tiers[r.Key]; dup {
			t.Errorf("%s is listed twice: %+v", r.Key, got)
		}
		tiers[r.Key] = r.Tier
	}
	if tiers["http://t.test/api"] != proof.TierFinding || tiers["http://t.test/bare"] != proof.TierLead || len(got) != 2 {
		t.Errorf("tiers %v, want /api a finding and /bare a lead", tiers)
	}
}

// /assets that answers an empty 302 and /assets/ that answers 500 with a trace
// are one route: the 5xx reason names the URL that gave it, so the 302 is not
// read as the answer that failed (#588).
func TestServerErrorNamesTheURLOfAFoldedRoute(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"url": "http://t.test/assets/", "status": 500, "error_text": "stack", "error_sample": "Traceback (most recent call last)"})
	got := Build(Input{DB: "w.db", Now: time.Now(), Since: 7 * 24 * time.Hour,
		Rows: []engine.MapEntry{
			urlRow("http://t.test/assets", "page", "visited", 302, nil),
			urlRow("http://t.test/assets/", "page", "visited", 500, nil),
		},
		Obs: []types.StoredObservation{{EntityID: "http://t.test/assets/", Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: payload}}}})
	r := find(got, "http://t.test/assets")
	if r == nil || len(r.Reasons) != 1 || r.Reasons[0].Detail != `http://t.test/assets/ answers 500 with a stack trace: "Traceback (most recent call last)"` {
		t.Errorf("row %+v", r)
	}
}
