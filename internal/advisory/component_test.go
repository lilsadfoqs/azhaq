package advisory

import (
	"strings"
	"testing"
)

// A record whose own CNA names another product than the one it is matched
// under says so, and ranks after the product's own advisories, whatever its
// score: the first advisory of a database service is no longer a library's.
func TestAdvisoryOfAnotherComponentRanksAfterTheProductsOwn(t *testing.T) {
	ix := NewIndex(IndexMeta{Built: "2026-11-16", Records: 3, Names: map[string][]string{ProductKey("MySQL"): {"oracle:mysql_server"}}},
		[]IndexProduct{{CPE: "oracle:mysql_server", Vulns: []IndexVuln{
			{ID: "CVE-2000-0001", CVSS: 9.8, Ranges: []string{"[|9.0)"}, Comp: []string{"libclient"}}, // a library's record, the best score
			{ID: "CVE-2000-0002", CVSS: 6.5, Ranges: []string{"[|9.0)"}},                              // the product's own
			{ID: "CVE-2000-0003", CVSS: 7.1, KEV: true, Ranges: []string{"[|9.0)"}, Comp: []string{"zlib", "libpng"}},
		}}})
	svc := []Service{{Host: "db", Port: 3306, Proto: "tcp", Service: "mysql", Product: "MySQL", Version: "8.0.1"}}
	leads, _, err := MatchAll(svc, nil, ix)
	if err != nil {
		t.Fatal(err)
	}
	if len(leads) != 3 || leads[0].AdvisoryID != "CVE-2000-0002" || leads[0].Component != "" {
		t.Fatalf("first match %+v", leads[0])
	}
	g := Group(leads)
	if len(g) != 1 || g[0].AdvisoryID != "CVE-2000-0002" || g[0].Component != "" || g[0].CVSS != 6.5 {
		t.Fatalf("top of the lead %+v", g[0])
	}
	var comps []string
	for _, r := range g[0].Advisories {
		comps = append(comps, r.ID+"="+r.Component)
	}
	if got := strings.Join(comps, " "); got != "CVE-2000-0002= CVE-2000-0003=zlib, libpng CVE-2000-0001=libclient" {
		t.Errorf("advisories %s", got)
	}
	// The label is unchanged: a version inside the range is still affected, and the counts say so.
	if g[0].Counts[LabelAffected] != 3 || g[0].MaxCVSS != 9.8 {
		t.Errorf("counts %v max %.1f", g[0].Counts, g[0].MaxCVSS)
	}
	// The component survives the stored row: expanded, each advisory keeps its own.
	ex := g[0].Expand()
	if ex[1].Component != "zlib, libpng" || ex[0].Component != "" {
		t.Errorf("expanded %q %q", ex[0].Component, ex[1].Component)
	}
	// A lead whose own top names another says it on its line.
	line := leads[2].Line()
	if !strings.Contains(line, "the record's own CNA names libclient, not MySQL") {
		t.Errorf("line %q", line)
	}
	if strings.Contains(leads[0].Line(), "own CNA names") {
		t.Errorf("the product's own advisory says another: %q", leads[0].Line())
	}
	// A record filed twice (under two names of the product), once with the
	// product's own name, is the product's own.
	ix2 := NewIndex(IndexMeta{Names: map[string][]string{ProductKey("MySQL"): {"a:mysql", "b:mysql"}}}, []IndexProduct{
		{CPE: "a:mysql", Vulns: []IndexVuln{{ID: "CVE-2000-0009", Ranges: []string{"[|9.0)"}, Comp: []string{"x"}}}},
		{CPE: "b:mysql", Vulns: []IndexVuln{{ID: "CVE-2000-0009", Ranges: []string{"[|9.0)"}}}},
	})
	l2, err := MatchIndex(svc, ix2)
	if err != nil || len(l2) != 1 || l2[0].Component != "" {
		t.Errorf("one record under two names: %+v %v", l2, err)
	}
}
