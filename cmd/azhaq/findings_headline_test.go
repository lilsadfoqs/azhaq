package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/proof"
)

var headlineRe = regexp.MustCompile(`(\d+) findings?(?: \((\d+) records?\))?, (\d+) identifications?(?: \((\d+) records?\))?, (\d+) leads?(?: \((\d+) records?\))?`)

// The findings headline says the issues and, where they differ, the records:
// the record count of a tier is the number of JSONL rows of that tier, and
// the headline never calls a count a stored row.
func checkHeadline(t *testing.T, set findingSet) {
	t.Helper()
	md := string(findingsMarkdown(set))
	m := headlineRe.FindStringSubmatch(md)
	if m == nil {
		t.Fatalf("no headline in %.300q", md)
	}
	if strings.Contains(md, "stored row") {
		t.Errorf("the headline says a count is a stored row: %.300q", md)
	}
	num := func(i int) int { n, _ := strconv.Atoi(m[i]); return n }
	records := func(issue, rec int) int {
		if m[rec] == "" {
			return num(issue)
		}
		return num(rec)
	}
	fs, is, lds := parseTiers(t, findingsJSONL(set))
	for _, c := range []struct {
		tier         string
		issue, rec   int
		rows, issues int
	}{
		{"finding", 1, 2, len(fs), set.counts().Findings},
		{"identification", 3, 4, len(is), set.counts().Identifications},
		{"lead", 5, 6, len(lds), set.counts().Leads},
	} {
		if num(c.issue) != c.issues {
			t.Errorf("%s: headline says %d issues, the tier counts %d", c.tier, num(c.issue), c.issues)
		}
		if got := records(c.issue, c.rec); got != c.rows {
			t.Errorf("%s: headline says %d records, the JSONL holds %d rows", c.tier, got, c.rows)
		}
	}
	if want := set.headline(); !strings.Contains(md, want) {
		t.Errorf("markdown lacks the headline %q", want)
	}
}

func TestFindingsHeadlineCountsRecordsAndIssues(t *testing.T) {
	var set findingSet
	set.Findings = []findingRecord{{Tier: proof.TierFinding, Kind: "secret", Host: "a", Port: 80}}
	for i := 0; i < 17; i++ { // 17 advisory records of two leads
		lead := "a:80 nginx"
		if i%2 == 1 {
			lead = "a:80 Jetty"
		}
		set.Identifications = append(set.Identifications, findingRecord{Tier: proof.TierIdentification, Label: "version-only", Host: "a", Port: 80,
			AdvisoryID: fmt.Sprintf("CVE-%d", i), Lead: lead})
	}
	set.Leads = []findingRecord{{Tier: proof.TierLead, Kind: "hint", Host: "a"}, {Tier: proof.TierLead, Kind: "hint", Host: "b"}}
	if got, want := set.headline(), "1 finding, 2 identifications (17 records), 2 leads"; got != want {
		t.Errorf("headline %q, want %q", got, want)
	}
	checkHeadline(t, set)
	// Where records and issues agree, no second number.
	set.Identifications = set.Identifications[:1]
	if got, want := set.headline(), "1 finding, 1 identification, 2 leads"; got != want {
		t.Errorf("headline %q, want %q", got, want)
	}
	checkHeadline(t, set)
}

func TestFindingsHeadlineOfARunMatchesItsJSONL(t *testing.T) {
	_, _, obs := runListenerStage(t)
	set := buildFindings(&graphView{obs: obs, args: []string{"-url", "http://app.test:8080/"}})
	if got, want := set.headline(), "0 findings, 2 identifications (7 records), 0 leads"; got != want {
		t.Errorf("headline %q, want %q", got, want)
	}
	checkHeadline(t, set)
}
