package advisory_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

func vectorIndex() *advisory.Index {
	meta := advisory.IndexMeta{Generator: advisory.IndexGenerator, Built: "2026-11-17", Records: 6, Names: map[string][]string{advisory.ProductKey("Widget"): {"acme:widget"}}}
	rng := []string{"[1.0|2.0)"}
	return advisory.NewIndex(meta, []advisory.IndexProduct{{CPE: "acme:widget", Vulns: []advisory.IndexVuln{
		{ID: "CVE-2021-1000", CVSS: 9.8, Ranges: rng},
		{ID: "CVE-2021-1001", CVSS: 7.8, Ranges: rng, AV: advisory.AVLocal},
		{ID: "CVE-2021-1002", CVSS: 6.8, Ranges: rng, AV: advisory.AVPhysical},
		{ID: "CVE-2021-1003", CVSS: 7.0, Ranges: rng, AV: advisory.AVLocal, Cond: advisory.CondPlatform},
		{ID: "CVE-2021-1004", CVSS: 7.0, Ranges: []string{"[3.0|4.0)"}, AV: advisory.AVLocal},
		{ID: "CVE-2021-1005", CVSS: 5.0, Ranges: rng, Cond: advisory.CondEdition},
	}}})
}

// A match whose record's attack vector is local or physical is conditional,
// with the condition taken from the vector; a network record is unchanged,
// and a record the version is outside of stays not affected.
func TestLocalAndPhysicalRecordsAreConditional(t *testing.T) {
	leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: "Widget", Version: "1.5"}}, vectorIndex())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]advisory.Lead{}
	for _, l := range leads {
		by[l.AdvisoryID] = l
	}
	if l := by["CVE-2021-1000"]; l.Label != advisory.LabelAffected || l.Precondition != "" {
		t.Errorf("a network record: %+v", l)
	}
	if l := by["CVE-2021-1001"]; l.Label != advisory.LabelConditional || !strings.HasPrefix(l.Precondition, "needs local access") || !strings.Contains(l.Precondition, "AV:L") {
		t.Errorf("a local record: %q %q", l.Label, l.Precondition)
	}
	if l := by["CVE-2021-1002"]; l.Label != advisory.LabelConditional || !strings.HasPrefix(l.Precondition, "needs physical access") || !strings.Contains(l.Precondition, "AV:P") {
		t.Errorf("a physical record: %q %q", l.Label, l.Precondition)
	}
	// Both conditions are said when the record has the two.
	if l := by["CVE-2021-1003"]; l.Label != advisory.LabelConditional || !strings.HasPrefix(l.Precondition, "needs local access") || !strings.Contains(l.Precondition, "runs with") {
		t.Errorf("a local record that names a platform: %q", l.Precondition)
	}
	if l := by["CVE-2021-1004"]; l.Label != advisory.LabelNotAffected || l.Precondition != "" {
		t.Errorf("a local record the version is outside of: %+v", l)
	}
	if l := by["CVE-2021-1005"]; l.Label != advisory.LabelConditional || strings.Contains(l.Precondition, "needs ") {
		t.Errorf("an edition record names no vector: %q", l.Precondition)
	}
	// The lead of the service counts them as conditional, and ranks the matches as before.
	g := advisory.Group(leads)[0]
	if g.Counts[advisory.LabelAffected] != 1 || g.Counts[advisory.LabelConditional] != 4 || g.Counts[advisory.LabelNotAffected] != 1 {
		t.Errorf("counts %v", g.Counts)
	}
	// The confirmation read finds the record with its condition.
	adv, ok := vectorIndex().Advisory("Widget", "CVE-2021-1001")
	if !ok || !strings.HasPrefix(adv.Precondition, "needs local access") {
		t.Errorf("advisory %+v", adv)
	}
}

// The vector is in the index file: written and read again, it is kept.
func TestIndexFileKeepsTheAttackVector(t *testing.T) {
	ix := vectorIndex()
	products := []advisory.IndexProduct{{CPE: "acme:widget", Vulns: []advisory.IndexVuln{
		{ID: "CVE-2021-1001", Ranges: []string{"[1.0|2.0)"}, AV: advisory.AVLocal},
		{ID: "CVE-2021-1000", Ranges: []string{"[1.0|2.0)"}},
	}}}
	var b bytes.Buffer
	if err := advisory.WriteIndex(&b, ix.Meta(), products); err != nil {
		t.Fatal(err)
	}
	back, err := advisory.ReadIndex(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: "Widget", Version: "1.5"}}, back)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range leads {
		got[l.AdvisoryID] = l.Label
	}
	if got["CVE-2021-1001"] != advisory.LabelConditional || got["CVE-2021-1000"] != advisory.LabelAffected {
		t.Errorf("labels after a round trip: %v", got)
	}
}

// A line of a service with fifty advisories names the top three and counts
// the rest by label; the lead still lists all fifty.
func TestLineNamesTheTopAndCountsTheRestByLabel(t *testing.T) {
	var leads []advisory.Lead
	for i := 0; i < 50; i++ {
		label := advisory.LabelAffected
		switch {
		case i >= 45:
			label = advisory.LabelNotAffected
		case i >= 35:
			label = advisory.LabelConditional
		}
		leads = append(leads, advisory.Lead{AdvisoryID: fmt.Sprintf("CVE-2021-%04d", i), Label: label, CVSS: 9.0 - float64(i)/10, KEV: i == 1,
			Target: "h:80", Host: "h", Port: 80, Product: "Widget", VersionSeen: "1.5"})
	}
	g := advisory.Group(leads)[0]
	if len(g.Advisories) != 50 {
		t.Fatalf("%d advisories in the lead", len(g.Advisories))
	}
	line := g.Line()
	// KEV first, then the score: CVE-2021-0001, then 0000 and 0002; 47 others by label.
	for _, want := range []string{"top CVE-2021-0001 ", "; then CVE-2021-0000 (affected, CVSS 9.0), CVE-2021-0002 (affected, CVSS 8.8) and 47 more: 32 affected, 10 conditional, 5 not affected"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, "CVE-2021-0003") {
		t.Errorf("a fourth advisory is named: %q", line)
	}
	top, more, rest := g.Fold(advisory.TopAdvisories)
	if len(top) != 3 || more != 47 || rest != "32 affected, 10 conditional, 5 not affected" {
		t.Errorf("fold %v %d %q", top, more, rest)
	}
	// A service with few advisories has nothing to fold.
	small := advisory.Group(leads[:2])[0]
	if strings.Contains(small.Line(), " more") {
		t.Errorf("line of two advisories %q", small.Line())
	}
}
