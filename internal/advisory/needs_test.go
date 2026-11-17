package advisory

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

const (
	quoteH2      = "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly."
	quoteRewrite = "Improper escaping of output in mod_rewrite in Apache HTTP Server allows an attacker to map URLs to filesystem locations."
)

// needsIndex is a product with three version matches: a plain one that
// scores 5.0, and two that state a precondition in their text and score
// higher (one of them on CISA KEV).
func needsIndex() *Index {
	meta := IndexMeta{Generator: IndexGenerator, Built: "2026-11-17", Records: 4, Names: map[string][]string{ProductKey("Widget"): {"acme:widget"}}}
	rng := []string{"[1.0|2.0)"}
	return NewIndex(meta, []IndexProduct{{CPE: "acme:widget", Vulns: []IndexVuln{
		{ID: "CVE-2023-0001", CVSS: 5.0, Ranges: rng},
		{ID: "CVE-2023-44487", CVSS: 7.5, KEV: true, Ranges: rng, Needs: []Need{{NeedHTTP2, quoteH2}}},
		{ID: "CVE-2024-38475", CVSS: 9.1, Ranges: rng, Needs: []Need{{"mod_rewrite", quoteRewrite}}},
		{ID: "CVE-2023-0004", CVSS: 6.0, Ranges: rng, Needs: []Need{{NeedHTTP2, quoteH2}}, AV: AVLocal},
		{ID: "CVE-2023-0005", CVSS: 8.0, Ranges: []string{"[3.0|4.0)"}, Needs: []Need{{NeedHTTP2, quoteH2}}},
	}}})
}

func leadsOf(t *testing.T, svc Service) map[string]Lead {
	t.Helper()
	leads, err := MatchIndex([]Service{svc}, needsIndex())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Lead{}
	for _, l := range leads {
		by[l.AdvisoryID] = l
	}
	return by
}

// A match whose record states a precondition is conditional, with the
// condition and its quote; a plain match is affected; a record the version is
// outside of stays not affected, whatever it states.
func TestAMatchWithAStatedNeedIsConditional(t *testing.T) {
	by := leadsOf(t, Service{Host: "h", Port: 80, Product: "Widget", Version: "1.5"})
	if l := by["CVE-2023-0001"]; l.Label != LabelAffected || l.Precondition != "" || len(l.Needs) != 0 {
		t.Errorf("a plain match: %+v", l)
	}
	l := by["CVE-2023-44487"]
	if l.Label != LabelConditional || l.Precondition != `needs HTTP/2: "`+quoteH2+`"` || len(l.Needs) != 1 || l.Needs[0] != "HTTP/2" || l.Settled != "" {
		t.Errorf("a protocol: %q %q %v", l.Label, l.Precondition, l.Needs)
	}
	if l := by["CVE-2024-38475"]; l.Label != LabelConditional || !strings.HasPrefix(l.Precondition, `needs mod_rewrite: "Improper escaping`) {
		t.Errorf("a module: %q %q", l.Label, l.Precondition)
	}
	// The needs follow what the record's configuration gave (here the vector).
	if l := by["CVE-2023-0004"]; !strings.HasPrefix(l.Precondition, "needs local access") || !strings.Contains(l.Precondition, `; needs HTTP/2: "`) {
		t.Errorf("a vector and a protocol: %q", l.Precondition)
	}
	if l := by["CVE-2023-0005"]; l.Label != LabelNotAffected || l.Precondition != "" || len(l.Needs) != 0 {
		t.Errorf("out of range: %+v", l)
	}
	if !strings.Contains(l.Line(), `precondition: needs HTTP/2: "`) {
		t.Errorf("line %q", l.Line())
	}
}

// The service's lead ranks the plain match first though the others score
// higher and one is on KEV: a conditional match ranks below a version-only
// match with nothing open. The list keeps every one.
func TestAMatchWithAnOpenNeedRanksBelowAPlainOne(t *testing.T) {
	leads, err := MatchIndex([]Service{{Host: "h", Port: 80, Product: "Widget", Version: "1.5"}}, needsIndex())
	if err != nil {
		t.Fatal(err)
	}
	g := Group(leads)[0]
	if g.AdvisoryID != "CVE-2023-0001" || g.Label != LabelAffected {
		t.Fatalf("top %s %s", g.AdvisoryID, g.Label)
	}
	var order []string
	for _, r := range g.Advisories {
		order = append(order, r.ID+" "+r.Label)
	}
	want := "CVE-2023-0001 affected, CVE-2023-44487 conditional, CVE-2024-38475 conditional, CVE-2023-0004 conditional, CVE-2023-0005 not affected"
	if got := strings.Join(order, ", "); got != want {
		t.Errorf("order %q, want %q", got, want)
	}
	// Told in a summary, a conditional one names what it waits on.
	if r := g.Advisories[1]; r.Tags() != "conditional: needs HTTP/2, KEV, CVSS 7.5" {
		t.Errorf("tags %q", r.Tags())
	}
	if !strings.Contains(g.Line(), "then CVE-2023-44487 (conditional: needs HTTP/2, KEV, CVSS 7.5), CVE-2024-38475 (conditional: needs mod_rewrite, CVSS 9.1)") {
		t.Errorf("line %q", g.Line())
	}
	// Expanded again, the records keep their conditions.
	for _, e := range g.Expand() {
		if e.AdvisoryID == "CVE-2023-44487" && (e.Label != LabelConditional || !strings.Contains(e.Precondition, quoteH2) || len(e.Needs) != 1) {
			t.Errorf("expanded %+v", e)
		}
	}
}

// Where the run saw the listener speak HTTP/2, the need is settled: the
// match is a plain one again and says what settled it. A need nothing
// measured stays open.
func TestAnObservedH2SettlesTheNeed(t *testing.T) {
	by := leadsOf(t, Service{Host: "h", Port: 443, Product: "Widget", Version: "1.5", H2: "ALPN h2"})
	l := by["CVE-2023-44487"]
	if l.Label != LabelAffected || l.Precondition != "" || len(l.Needs) != 0 || l.Settled != "HTTP/2 offered (ALPN h2)" {
		t.Errorf("settled: %+v", l)
	}
	if !strings.Contains(l.Line(), "settled: HTTP/2 offered (ALPN h2)") {
		t.Errorf("line %q", l.Line())
	}
	if l := by["CVE-2024-38475"]; l.Label != LabelConditional || l.Settled != "" {
		t.Errorf("a module is not settled by HTTP/2: %+v", l)
	}
	// A record with another condition besides: that one stays open.
	if l := by["CVE-2023-0004"]; l.Label != LabelConditional || strings.Contains(l.Precondition, "HTTP/2") || l.Settled == "" {
		t.Errorf("vector stays open: %q %q", l.Label, l.Precondition)
	}
	// With the settled need, the plain and the settled one both come before the rest.
	leads, _ := MatchIndex([]Service{{Host: "h", Port: 443, Product: "Widget", Version: "1.5", H2: "ALPN h2"}}, needsIndex())
	if g := Group(leads)[0]; g.AdvisoryID != "CVE-2023-44487" || g.Label != LabelAffected {
		t.Errorf("top %s %s", g.AdvisoryID, g.Label)
	}
}

// The probe's http2 field, stored on a web row, is how the run saw HTTP/2:
// ALPN h2 on an https origin, an upgrade to h2c on http; a row without it
// says nothing.
func TestServicesCarryTheH2TheProbeRecorded(t *testing.T) {
	row := func(url string, h2 bool) types.StoredObservation {
		r := map[string]any{"url": url, "server": "Widget/1.5"}
		if h2 {
			r["http2"] = true
		}
		return obsOf("azhaq-http", "http", r)
	}
	for _, c := range []struct {
		url  string
		h2   bool
		want string
	}{{"https://app.test:8443/", true, "ALPN h2"}, {"http://app.test:8080/", true, "h2c upgrade"}, {"https://app.test:8443/", false, ""}} {
		got := Services([]types.StoredObservation{row(c.url, c.h2)})
		if len(got) != 1 || got[0].H2 != c.want {
			t.Errorf("%s http2=%v: %+v, want H2 %q", c.url, c.h2, got, c.want)
		}
	}
}

// The needs are in the index file: written and read again, they are kept.
func TestIndexFileKeepsTheNeeds(t *testing.T) {
	ix := needsIndex()
	products := []IndexProduct{{CPE: "acme:widget", Vulns: []IndexVuln{
		{ID: "CVE-2023-44487", Ranges: []string{"[1.0|2.0)"}, Needs: []Need{{NeedHTTP2, quoteH2}}},
		{ID: "CVE-2023-0001", Ranges: []string{"[1.0|2.0)"}},
	}}}
	var b bytes.Buffer
	if err := WriteIndex(&b, ix.Meta(), products); err != nil {
		t.Fatal(err)
	}
	back, err := ReadIndex(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	leads, err := MatchIndex([]Service{{Host: "h", Port: 80, Product: "Widget", Version: "1.5"}}, back)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range leads {
		got[l.AdvisoryID] = l.Label + "|" + l.Precondition
	}
	if got["CVE-2023-44487"] != `conditional|needs HTTP/2: "`+quoteH2+`"` || got["CVE-2023-0001"] != "affected|" {
		t.Errorf("after a round trip: %v", got)
	}
	adv, ok := back.Advisory("Widget", "CVE-2023-44487")
	if !ok || len(adv.Needs) != 1 || adv.Needs[0].Quote != quoteH2 {
		t.Errorf("advisory %+v", adv)
	}
}

// A confirmation read that states the version settles the range but not a
// need the record's text states: inferred, naming it. Where the run saw the
// need settled, the read observes.
func TestAReadDoesNotSettleAStatedNeed(t *testing.T) {
	adv, ok := needsIndex().Advisory("Widget", "CVE-2023-44487")
	if !ok {
		t.Fatal("no advisory")
	}
	sig := Signal{What: "GET /", Product: "Widget", Version: "1.5", From: "its Server header"}
	conf, read := sig.Judge(adv, Service{Product: "Widget", Version: "1.5"})
	if conf != Inferred || !strings.Contains(read, "needs HTTP/2") {
		t.Errorf("open need: %s, %q", conf, read)
	}
	if conf, _ := sig.Judge(adv, Service{Product: "Widget", Version: "1.5", H2: "ALPN h2"}); conf != Observed {
		t.Errorf("settled need: %s", conf)
	}
}
