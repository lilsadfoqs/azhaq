package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// listenerAdvisories: five version-range matches of nginx, and one advisory
// with a stated precondition that names both nginx and Jetty.
func listenerAdvisories() string {
	var recs []string
	for i := 1; i <= 5; i++ {
		recs = append(recs, fmt.Sprintf(`{"id":"CVE-TEST-%04d","affected":[{"package":{"name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}]}`, i))
	}
	recs = append(recs, `{"id":"CVE-TEST-0100","azhaq_precondition":"only with the example module",
	  "affected":[{"package":{"name":"nginx"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]},
	              {"package":{"name":"Jetty"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"9.0.0"},{"fixed":"9.4.53"}]}]}]}`)
	return "[" + strings.Join(recs, ",") + "]"
}

func listenerObs() []types.StoredObservation {
	row := func(collector, kind string, p map[string]any) types.StoredObservation {
		raw, _ := json.Marshal(p)
		return types.StoredObservation{Observation: types.Observation{Collector: collector, Kind: kind, Payload: raw}}
	}
	return []types.StoredObservation{
		// One listener reached by its name and by its address, naming Jetty twice.
		row("azhaq-http", "http", map[string]any{"url": "http://app.test:8080/", "ip": "10.0.0.5", "server": "Jetty/9.4.z-SNAPSHOT", "tech": []string{"Jetty:9.4"}}),
		row("azhaq-http", "http", map[string]any{"url": "http://10.0.0.5:8080/", "ip": "10.0.0.5", "server": "Jetty/9.4.z-SNAPSHOT"}),
		row("azhaq-ports", "ports", map[string]any{"host": "10.0.0.5", "ip": "10.0.0.5",
			"services": []map[string]any{{"port": 8080, "service": "http", "product": "nginx", "version": "1.18.0"}}}),
	}
}

func runListenerStage(t *testing.T) (leadsJSON []map[string]any, note string, obs []types.StoredObservation) {
	t.Helper()
	egress.Reset()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	in := listenerObs()
	leads, failures, note := advisoryStage(context.Background(), st, in, advisoryFlags{on: true, source: writeAdvFixture(t, listenerAdvisories())})
	if len(failures) > 0 {
		t.Fatalf("failures %v", failures)
	}
	for _, l := range leads {
		raw, _ := json.Marshal(l)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		leadsJSON = append(leadsJSON, m)
	}
	stored, _ := st.Observations()
	return leadsJSON, note, append(in, stored...)
}

// One lead for a listener and product: the name and the address are one, the
// header and the page's technology are one version, and a version that
// cannot be ordered is conditional with its reason.
func TestAdvisoryLeadIsOnePerListenerAndProduct(t *testing.T) {
	leads, _, _ := runListenerStage(t)
	if len(leads) != 2 {
		t.Fatalf("%d leads, want 2 (nginx and Jetty on one listener): %v", len(leads), leads)
	}
	var jetty map[string]any
	for _, l := range leads {
		if l["product"] == "Jetty" {
			jetty = l
		}
	}
	if jetty == nil || jetty["version_seen"] != "9.4.z-SNAPSHOT" || jetty["target"] != "app.test:8080" || jetty["address"] != "10.0.0.5" {
		t.Fatalf("jetty lead %v, want the most specific version on app.test:8080 at 10.0.0.5", jetty)
	}
	if names, _ := jetty["names"].([]any); len(names) != 2 {
		t.Errorf("names %v, want the name and the address", jetty["names"])
	}
	if jetty["label"] != "conditional" || !strings.Contains(fmt.Sprint(jetty["precondition"]), "could not be compared") {
		t.Errorf("jetty %v %v, want conditional with the reason, never not affected", jetty["label"], jetty["precondition"])
	}
}

// The summary counts the distinct advisories: CVE-TEST-0100 names both
// products of the listener and is one.
func TestAdvisoryNoteCountsDistinctAdvisories(t *testing.T) {
	_, note, _ := runListenerStage(t)
	want := "2 leads, one for each of 2 confirmed products on 1 listeners, holding 6 distinct advisories (5 affected, 0 not affected, 1 conditional;"
	if !strings.Contains(note, want) {
		t.Errorf("note %q lacks %q", note, want)
	}
}

// The tiers count issues, not records: the range matches of a lead (CVE-TEST-0100
// among them, conditional) are one identification for each lead; the export lists every record and each names its lead.
func TestFindingTiersCountIssuesAndRecordsNameTheirLead(t *testing.T) {
	_, _, obs := runListenerStage(t)
	set := buildFindings(&graphView{obs: obs, args: []string{"-url", "http://app.test:8080/"}})
	if len(set.Identifications) != 7 {
		t.Fatalf("%d identification records, want 7 (6 for nginx, 1 for Jetty)", len(set.Identifications))
	}
	if c := set.counts(); c.Identifications != 2 {
		t.Errorf("tier counts %+v, want 2 identifications (one for each lead's range matches)", c)
	}
	leads := map[string]int{}
	for _, r := range set.Identifications {
		if r.Lead == "" {
			t.Errorf("record %s has no lead", r.AdvisoryID)
		}
		leads[r.Lead]++
		if r.Label == verify.VersionOnly && r.Product != "nginx" {
			t.Errorf("record %+v", r)
		}
	}
	if leads["app.test:8080 nginx"] != 6 || leads["app.test:8080 Jetty"] != 1 {
		t.Errorf("records by lead %v", leads)
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(findingsJSONL(set))), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 7 || lines[0]["lead"] == nil {
		t.Errorf("%d export lines, want one for each advisory record, each with its lead: %v", len(lines), lines[0])
	}
	if md := string(findingsMarkdown(set)); !strings.Contains(md, "0 findings, 2 identifications, 0 leads") {
		t.Errorf("markdown counts %q", md[:200])
	}
}

// An advisory counts on its own only when a read that answered settled
// something of it; the range matches, conditional ones too, are one per lead.
func TestFindingTiersFoldRangeMatchesAndCountChecked(t *testing.T) {
	lead := advisory.Lead{AdvisoryID: "CVE-A", Label: "affected", Target: "app.test:80", Host: "app.test", Port: 80, Product: "nginx", VersionSeen: "1.18.0",
		Advisories: []advisory.Ref{
			{ID: "CVE-A", Label: "affected", Confidence: advisory.Observed},
			{ID: "CVE-B", Label: "conditional", Precondition: "p", Confidence: advisory.Claimed},
			{ID: "CVE-C", Label: "conditional", Precondition: "p"},
			{ID: "CVE-D", Label: "affected", Confidence: advisory.Inferred},
			{ID: "CVE-E", Label: "affected", KEV: true},
		}}
	raw, _ := json.Marshal(lead)
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-advisories", Kind: "advisory", Payload: raw}}}
	set := buildFindings(&graphView{obs: obs, args: []string{"-url", "http://app.test/"}})
	if len(set.Identifications) != 5 {
		t.Fatalf("%d records, want 5", len(set.Identifications))
	}
	if c := set.counts(); c.Identifications != 3 {
		t.Errorf("%d identifications, want 3 (CVE-A and CVE-D were read; B, C and the KEV E are the lead's range matches)", c.Identifications)
	}
}
