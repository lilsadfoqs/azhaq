package hunt

import (
	"fmt"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/proof"
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
