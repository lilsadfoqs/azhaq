package advisory_test

import (
	"os"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/advisory/build"
)

// pinnedIndex is the index the generator makes from the pinned snapshot of
// public records in build/testdata: real CISA KEV and NVD records of
// products of each class, kept as they were published.
func pinnedIndex(t *testing.T) *advisory.Index {
	t.Helper()
	read := func(name string) string {
		raw, err := os.ReadFile("build/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	m, err := build.ParseMap(strings.NewReader(read("cpemap.tsv")))
	if err != nil {
		t.Fatal(err)
	}
	res, err := build.Build(build.Options{
		KEV: []byte(read("kev.json")), Feeds: []build.Feed{{Name: "pinned", R: strings.NewReader(read("nvd-pinned.json"))}},
		Map: m, Built: "2026-11-12",
	})
	if err != nil {
		t.Fatal(err)
	}
	return advisory.NewIndex(res.Meta, res.Products)
}

// pair is a product and version a run confirmed, and what the index says of
// one advisory for it.
type pair struct {
	product, version, id, label string
}

// The pairs are read off the records themselves: a version inside a range
// or on a listed version, the first one outside, and the boundaries on
// both sides, for each class of product.
var pairs = []pair{
	// web server
	{"Apache httpd", "2.4.49", "CVE-2021-41773", "affected"}, // listed
	{"Apache httpd", "2.4.48", "CVE-2021-41773", "not affected"},
	{"Apache httpd", "2.4.50", "CVE-2021-41773", "not affected"},
	{"Apache httpd", "2.4.51", "CVE-2021-41773", "not affected"},
	{"Apache httpd", "2.4.17", "CVE-2019-0211", "affected"},     // start included
	{"Apache httpd", "2.4.38", "CVE-2019-0211", "affected"},     // end included
	{"Apache httpd", "2.4.39", "CVE-2019-0211", "not affected"}, // just past it
	{"Apache httpd", "2.4.16", "CVE-2019-0211", "not affected"}, // just before it
	{"Apache httpd", "2.0.50", "CVE-2010-0425", "conditional"},  // in range, and a platform is named
	{"Apache httpd", "2.0.64", "CVE-2010-0425", "not affected"},
	// application server
	{"Apache Tomcat", "9.0.30", "CVE-2020-1938", "affected"},
	{"Apache Tomcat", "9.0.31", "CVE-2020-1938", "not affected"},
	{"Apache Tomcat", "8.5.50", "CVE-2020-1938", "affected"},
	{"Apache Tomcat", "8.5.51", "CVE-2020-1938", "not affected"},
	{"Apache Tomcat", "7.0.99", "CVE-2020-1938", "affected"},
	{"Apache Tomcat", "7.0.100", "CVE-2020-1938", "not affected"},
	{"Apache Tomcat", "8.0.52", "CVE-2020-1938", "not affected"}, // a branch the record does not name
	{"Oracle WebLogic Server", "12.2.1.3.0", "CVE-2020-14882", "affected"},
	{"Oracle WebLogic Server", "12.2.1.2.0", "CVE-2020-14882", "not affected"},
	{"WebLogic Server", "14.1.1.0.0", "CVE-2020-14882", "not affected"}, // no map line for this name
	// database
	{"MongoDB", "7.0.27", "CVE-2025-14847", "affected"},
	{"MongoDB", "7.0.28", "CVE-2025-14847", "not affected"},
	{"MongoDB", "8.2.2", "CVE-2025-14847", "affected"},
	{"MongoDB", "8.2.3", "CVE-2025-14847", "not affected"},
	{"MongoDB", "4.4.29", "CVE-2025-14847", "affected"},
	{"MongoDB", "4.4.30", "CVE-2025-14847", "not affected"},
	{"MongoDB", "3.4.24", "CVE-2025-14847", "not affected"}, // before the first range
	{"Apache CouchDB", "3.2.1", "CVE-2022-24706", "affected"},
	{"Apache CouchDB", "3.2.2", "CVE-2022-24706", "not affected"},
	{"Elasticsearch", "1.4.2", "CVE-2015-1427", "affected"},
	{"Elasticsearch", "1.4.3", "CVE-2015-1427", "not affected"},
	{"Elasticsearch", "1.3.7", "CVE-2015-1427", "affected"},
	{"Elasticsearch", "1.3.8", "CVE-2015-1427", "not affected"}, // between the two ranges
	// message broker
	{"ActiveMQ", "5.17.3", "CVE-2023-46604", "affected"},
	{"ActiveMQ", "5.17.6", "CVE-2023-46604", "not affected"},
	{"ActiveMQ", "5.18.2", "CVE-2023-46604", "affected"},
	{"ActiveMQ", "5.18.3", "CVE-2023-46604", "not affected"},
	{"ActiveMQ", "5.16.7", "CVE-2023-46604", "not affected"},
	{"ActiveMQ", "5.15.15", "CVE-2023-46604", "affected"}, // an open start
	{"ActiveMQ", "5.15.16", "CVE-2023-46604", "not affected"},
	{"ActiveMQ", "5.13.0", "CVE-2016-3088", "affected"},
	{"ActiveMQ", "5.14.0", "CVE-2016-3088", "not affected"},
	{"ActiveMQ", "4.1.1", "CVE-2016-3088", "not affected"},
	// CI server
	{"Jenkins", "2.441", "CVE-2024-23897", "conditional"}, // a long-term and a weekly range: which the service is, is not seen
	{"Jenkins", "2.426.2", "CVE-2024-23897", "conditional"},
	{"Jenkins", "2.442", "CVE-2024-23897", "not affected"},
	{"TeamCity", "2023.11.3", "CVE-2024-27198", "affected"},
	{"TeamCity", "2023.11.4", "CVE-2024-27198", "not affected"},
	// CMS
	{"Drupal", "7.57", "CVE-2018-7600", "affected"}, // the last version of its range
	{"Drupal", "7.58", "CVE-2018-7600", "not affected"},
	{"Drupal", "8.4.5", "CVE-2018-7600", "affected"},
	{"Drupal", "8.5.0", "CVE-2018-7600", "affected"},
	{"Drupal", "8.5.1", "CVE-2018-7600", "not affected"},
	{"Drupal", "8.3.9", "CVE-2018-7600", "not affected"}, // between two branches
	{"Joomla", "4.0.0", "CVE-2023-23752", "affected"},
	{"Joomla", "4.2.7", "CVE-2023-23752", "affected"},
	{"Joomla", "4.2.8", "CVE-2023-23752", "not affected"},
	{"Joomla", "3.10.11", "CVE-2023-23752", "not affected"},
	// SSH server: a KEV record that holds on Alpine only, so conditional where the version is in range
	{"OpenSSH", "9.6p1", "CVE-2026-123158", "conditional"},
	{"OpenSSH", "10.6", "CVE-2026-123158", "conditional"}, // listed
	{"OpenSSH", "10.6p1", "CVE-2026-123158", "conditional"},
	{"OpenSSH", "10.7", "CVE-2026-123158", "not affected"},
}

func TestIndexMatchesProductAndVersionPairs(t *testing.T) {
	ix := pinnedIndex(t)
	for _, p := range pairs {
		leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: p.product, Version: p.version}}, ix)
		if err != nil {
			t.Fatal(err)
		}
		var got *advisory.Lead
		for i, l := range leads {
			if l.AdvisoryID == p.id {
				got = &leads[i]
			}
		}
		if got == nil {
			// A product with no map line for its name has no leads at all.
			if p.label == "not affected" && len(leads) == 0 && p.product == "WebLogic Server" {
				continue
			}
			t.Errorf("%s %s: no lead for %s (leads %d)", p.product, p.version, p.id, len(leads))
			continue
		}
		if got.Label != p.label {
			t.Errorf("%s %s / %s: %q (range %s), want %q", p.product, p.version, p.id, got.Label, got.AffectedRange, p.label)
		}
		if got.URL != "https://nvd.nist.gov/vuln/detail/"+p.id || got.Source == "" || got.VersionSeen != p.version {
			t.Errorf("%s %s / %s: lead %+v lacks its URL, source or version", p.product, p.version, p.id, got)
		}
	}
}

// Each lead carries what a reader needs: the advisory, its flags and score,
// the range as the record states it, and, for a conditional one, why.
func TestIndexLeadsCarryTheirEvidence(t *testing.T) {
	ix := pinnedIndex(t)
	leads, _ := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 8080, Product: "Apache Tomcat", Version: "9.0.30"}}, ix)
	var l advisory.Lead
	for _, c := range leads {
		if c.AdvisoryID == "CVE-2020-1938" {
			l = c
		}
	}
	if !l.KEV || l.CVSS != 9.8 || l.AffectedRange != ">=7.0.0 <7.0.100; >=8.5.0 <8.5.51; >=9.0.0 <9.0.31" || l.Target != "h:8080" {
		t.Errorf("lead %+v", l)
	}
	if !strings.Contains(l.Line(), "known exploited (CISA KEV)") || !strings.Contains(l.Line(), "CVSS 9.8") {
		t.Errorf("line %q", l.Line())
	}
	leads, _ = advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: "Jenkins", Version: "2.441"}}, ix)
	if len(leads) != 1 || leads[0].Label != "conditional" || !strings.Contains(leads[0].Precondition, "long-term") {
		t.Errorf("jenkins leads %+v", leads)
	}
	// A conditional lead says which: the range as the record states it, and
	// the platform that makes it conditional.
	leads, _ = advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 22, Product: "OpenSSH", Version: "9.6p1"}}, ix)
	if len(leads) != 1 || leads[0].AffectedRange != "<10.6; =10.6, =10.6-p1" || leads[0].Label != "conditional" || !strings.Contains(leads[0].Precondition, "alpinelinux:alpine_linux") {
		t.Fatalf("openssh leads %+v", leads)
	}
	if line := leads[0].Line(); !strings.Contains(line, "is conditional (range <10.6; =10.6, =10.6-p1)") || !strings.Contains(line, "precondition: the advisory's configuration also names what the product runs on or with (alpinelinux:alpine_linux)") {
		t.Errorf("line %q", line)
	}
	// A confirmation reads the record as an advisory of the product seen.
	adv, ok := ix.Advisory("Apache Tomcat", "CVE-2020-1938")
	if !ok || adv.ID != "CVE-2020-1938" || len(adv.Affected) != 1 || len(adv.Affected[0].Ranges) != 3 {
		t.Errorf("advisory %+v %v", adv, ok)
	}
}

// Only the leads worth a line are listed: the not-affected ones of a record
// off the KEV catalogue are counted.
func TestMatchAllListsNotableLeadsAndCountsTheRest(t *testing.T) {
	ix := pinnedIndex(t)
	svc := []advisory.Service{{Host: "h", Port: 80, Product: "Apache httpd", Version: "2.4.51"}}
	leads, quiet, err := advisory.MatchAll(svc, nil, ix)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, l := range leads {
		ids[l.AdvisoryID] = l.Label
	}
	// The KEV records say 2.4.51 is outside their ranges; the other record is only counted.
	if ids["CVE-2021-41773"] != "not affected" || ids["CVE-2019-0211"] != "not affected" || len(leads) != 2 || quiet != 1 {
		t.Errorf("leads %v quiet %d, want the two KEV records not affected and one counted", ids, quiet)
	}
	// The user's own records keep every label.
	user, err := advisory.Load([]byte(`[{"id":"X-1","affected":[{"package":{"name":"httpd"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0"},{"fixed":"2.4.0"}]}]}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	leads, _, _ = advisory.MatchAll(svc, user, ix)
	var gotUser bool
	for _, l := range leads {
		if l.AdvisoryID == "X-1" && l.Label == "not affected" && l.Source == "" {
			gotUser = true
		}
	}
	if !gotUser || len(leads) != 3 {
		t.Errorf("leads %+v, want the user's not-affected lead beside the index's", leads)
	}
}
