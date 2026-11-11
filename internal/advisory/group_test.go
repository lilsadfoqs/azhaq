package advisory

import (
	"fmt"
	"strings"
	"testing"
)

// Ninety advisories of one service are one lead: the ones that apply first,
// exploited before the rest, higher scores first, with the counts by label.
func TestGroupMakesOneLeadOfAServicesAdvisories(t *testing.T) {
	var leads []Lead
	add := func(id, label string, kev bool, cvss float64) {
		leads = append(leads, Lead{AdvisoryID: id, URL: "https://x/" + id, Label: label, KEV: kev, CVSS: cvss,
			Target: "h:80", Host: "h", Port: 80, Product: "Apache httpd", VersionSeen: "2.4.49", AffectedRange: "<2.5"})
	}
	for i := 0; i < 70; i++ {
		add(fmt.Sprintf("CVE-2020-%04d", i), LabelAffected, false, 5+float64(i%40)/10) // 5.0 to 8.9
	}
	for i := 0; i < 12; i++ {
		add(fmt.Sprintf("CVE-2021-%04d", i), LabelAffected, true, 6.0+float64(i)/10) // exploited
	}
	for i := 0; i < 5; i++ {
		add(fmt.Sprintf("CVE-2022-%04d", i), LabelConditional, false, 9.9)
	}
	add("CVE-2019-0001", LabelNotAffected, true, 10.0) // exploited, but does not apply
	add("CVE-2019-0002", LabelNotAffected, false, 9.0)
	add("CVE-2019-0003", LabelNotAffected, false, 9.0)
	// A second service, and a second version of the first, are not in its lead.
	leads = append(leads, Lead{AdvisoryID: "CVE-2018-0001", Label: LabelAffected, Target: "h:81", Product: "Apache httpd", VersionSeen: "2.4.49"})
	leads = append(leads, Lead{AdvisoryID: "CVE-2018-0002", Label: LabelAffected, Target: "h:80", Product: "Apache httpd", VersionSeen: "2.4.50"})
	if len(leads) != 92 {
		t.Fatalf("%d leads made", len(leads))
	}

	got := Group(leads)
	if len(got) != 3 {
		t.Fatalf("%d groups, want one for each of three services", len(got))
	}
	var g Lead
	for _, c := range got {
		if c.Target == "h:80" && c.VersionSeen == "2.4.49" {
			g = c
		}
	}
	if len(g.Advisories) != 90 || g.Counts[LabelAffected] != 82 || g.Counts[LabelConditional] != 5 || g.Counts[LabelNotAffected] != 3 {
		t.Fatalf("%d advisories, counts %v", len(g.Advisories), g.Counts)
	}
	// The top is the exploited one with the highest score, not the exploited
	// one that does not apply (10.0) and not the conditional 9.9.
	if g.AdvisoryID != "CVE-2021-0011" || !g.KEV || g.CVSS != 7.1 || g.Label != LabelAffected {
		t.Errorf("top %s %s kev %v %.1f", g.AdvisoryID, g.Label, g.KEV, g.CVSS)
	}
	if g.KEVCount != 12 || g.MaxCVSS != 9.9 {
		t.Errorf("kev %d max %.1f, want 12 and 9.9 (of those that apply)", g.KEVCount, g.MaxCVSS)
	}
	// Order: applying first; within, exploited first, then score, then id.
	for i := 1; i < len(g.Advisories); i++ {
		p, c := g.Advisories[i-1], g.Advisories[i]
		pa, ca := p.Label != LabelNotAffected, c.Label != LabelNotAffected
		switch {
		case pa != ca:
			if !pa {
				t.Fatalf("not affected %s before %s", p.ID, c.ID)
			}
		case p.KEV != c.KEV:
			if !p.KEV {
				t.Fatalf("%s before the exploited %s", p.ID, c.ID)
			}
		case p.CVSS != c.CVSS:
			if p.CVSS < c.CVSS {
				t.Fatalf("%s (%.1f) before %s (%.1f)", p.ID, p.CVSS, c.ID, c.CVSS)
			}
		case p.ID > c.ID:
			t.Fatalf("%s before %s", p.ID, c.ID)
		}
	}
	if g.Advisories[0].ID != g.AdvisoryID || g.Advisories[89].ID != "CVE-2019-0003" {
		t.Errorf("list runs %s ... %s", g.Advisories[0].ID, g.Advisories[89].ID)
	}
	// The line is one, with the counts and the top advisory.
	line := g.Line()
	for _, want := range []string{"advisory: Apache httpd 2.4.49 on h:80: 82 affected, 5 conditional, 3 not affected (12 on KEV; highest CVSS 9.9); top CVE-2021-0011 is affected", "known exploited (CISA KEV)"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %q", line, want)
		}
	}
	if brief := g.Brief(); brief != "Apache httpd 2.4.49: 82 affected, 5 conditional, 3 not affected (12 on KEV; highest CVSS 9.9), top CVE-2021-0011 (KEV, 7.1)" {
		t.Errorf("brief %q", brief)
	}
	// The list expands to the leads Match made, none lost.
	ex := g.Expand()
	if len(ex) != 90 || ex[0].AdvisoryID != g.AdvisoryID || ex[89].Label != LabelNotAffected || len(ex[5].Advisories) != 0 {
		t.Errorf("expanded to %d", len(ex))
	}
	if g.IDs(10) != strings.Join([]string{"CVE-2021-0011", "CVE-2021-0010", "CVE-2021-0009", "CVE-2021-0008", "CVE-2021-0007", "CVE-2021-0006", "CVE-2021-0005", "CVE-2021-0004", "CVE-2021-0003", "CVE-2021-0002"}, ", ")+" and 80 more" {
		t.Errorf("ids %q", g.IDs(10))
	}
	// A service with one advisory keeps the line of one.
	for _, c := range got {
		if c.Target == "h:81" && strings.Contains(c.Line(), "top ") {
			t.Errorf("a lead of one advisory says top: %q", c.Line())
		}
	}
}
