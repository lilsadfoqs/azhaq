package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/hunt"
)

// fiftyAdvisories is one service's identifications: thirty version-only and
// twenty conditional, no read settled, in the order buildFindings keeps them.
func fiftyAdvisories() findingSet {
	var set findingSet
	for i := 0; i < 50; i++ {
		label := "version-only"
		if i >= 30 {
			label = "conditional"
		}
		set.Identifications = append(set.Identifications, findingRecord{
			Tier: "identification", Kind: "advisory-precondition", Label: label, Severity: "info", Host: "10.0.0.5", Port: 3306,
			Product: "Widget", Version: "1.5", AdvisoryID: fmt.Sprintf("CVE-2021-%04d", i), CVSS: 9.9 - float64(i)/10, KEV: i == 7,
			Lead: "10.0.0.5:3306 Widget", Evidence: "e", Command: "azhaq run",
		})
	}
	sort.SliceStable(set.Identifications, func(i, j int) bool { return findingLess(set.Identifications[i], set.Identifications[j]) })
	return set
}

// The Markdown names the top advisories of a service and counts the rest by
// label, in one bullet; the JSON Lines keep a record for each of the fifty.
func TestFindingsMarkdownFoldsAServicesAdvisories(t *testing.T) {
	set := fiftyAdvisories()
	md := string(findingsMarkdown(set))
	bullets := 0
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "- **") {
			bullets++
		}
	}
	if bullets != 1 {
		t.Errorf("%d bullets, want one for the service:\n%s", bullets, md)
	}
	want := "CVE-2021-0007 (version-only, KEV, CVSS 9.2), CVE-2021-0000 (version-only, CVSS 9.9), CVE-2021-0001 (version-only, CVSS 9.8) and 47 more: 27 version-only, 20 conditional (50 advisories)"
	if !strings.Contains(md, want) {
		t.Errorf("markdown lacks %q:\n%s", want, md)
	}
	if strings.Contains(md, "CVE-2021-0003") {
		t.Errorf("a fourth advisory is named:\n%s", md)
	}
	// All fifty are one issue, in the section of the strongest label, once.
	if !strings.Contains(md, "## Identifications (1)") || !strings.Contains(md, "### Version-only (1)") || strings.Contains(md, "### Conditional") {
		t.Errorf("sections:\n%s", md)
	}
	jl := string(findingsJSONL(set))
	if n := strings.Count(jl, `"type":"identification"`); n != 50 {
		t.Errorf("%d identification lines, want 50", n)
	}
	if !strings.Contains(jl, `"advisory_id":"CVE-2021-0049"`) {
		t.Error("the last advisory is not in the JSON Lines")
	}
}

// A service whose advisories were settled by a read is not folded into the
// ones no read settled: each keeps its own label and its own bullet.
func TestFindingsMarkdownKeepsAReadSettledAdvisoryApart(t *testing.T) {
	set := fiftyAdvisories()
	read := findingRecord{Tier: "identification", Kind: "advisory-precondition", Label: "version-read", Severity: "info", Host: "10.0.0.5", Port: 3306,
		Product: "Widget", Version: "1.5", AdvisoryID: "CVE-2021-9999", Lead: "10.0.0.5:3306 Widget", Evidence: "e", Command: "azhaq run", checked: true}
	set.Identifications = append(set.Identifications, read)
	sort.SliceStable(set.Identifications, func(i, j int) bool { return findingLess(set.Identifications[i], set.Identifications[j]) })
	md := string(findingsMarkdown(set))
	if !strings.Contains(md, "### Version-read (1)") || !strings.Contains(md, "CVE-2021-9999") || !strings.Contains(md, "### Version-only (1)") {
		t.Errorf("markdown:\n%s", md)
	}
}

// A hunt row names the top advisories and counts the rest by label.
func TestHuntRowFoldsAServicesAdvisories(t *testing.T) {
	ls := listenersOf(fiftyAdvisories())
	if len(ls) != 1 {
		t.Fatalf("%d listener rows, want 1", len(ls))
	}
	l := ls[0].Ident
	if l.Advisories != 50 || len(l.Next) != 2 || l.Others["version-only"] != 27 || l.Others["conditional"] != 20 {
		t.Fatalf("row %+v", l)
	}
	rows := hunt.ListenerRows(ls, "w.db")
	var detail string
	for _, r := range rows[0].Reasons {
		if r.Signal == "advisory" {
			detail = r.Detail
		}
	}
	want := "50 advisories match this version, then CVE-2021-0000 (version-only, CVSS 9.9), CVE-2021-0001 (version-only, CVSS 9.8) and 47 more: 27 version-only, 20 conditional; azhaq report -findings -db w.db lists them"
	if !strings.Contains(detail, want) {
		t.Errorf("advisory reason %q lacks %q", detail, want)
	}
}
