package build

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pinned(t *testing.T) Options {
	t.Helper()
	m, err := ParseMap(strings.NewReader(string(read(t, "cpemap.tsv"))))
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		KEV: read(t, "kev.json"), KEVURL: "kev", NVDURL: "nvd",
		Feeds: []Feed{{Name: "pinned", R: strings.NewReader(string(read(t, "nvd-pinned.json")))}},
		Map:   m, Built: "2026-11-12",
	}
}

func vuln(p advisory.IndexProduct, id string) (advisory.IndexVuln, bool) {
	for _, v := range p.Vulns {
		if v.ID == id {
			return v, true
		}
	}
	return advisory.IndexVuln{}, false
}

func product(res *Result, cpe string) advisory.IndexProduct {
	for _, p := range res.Products {
		if p.CPE == cpe {
			return p
		}
	}
	return advisory.IndexProduct{}
}

// The index built from the pinned KEV and NVD records holds the ranges,
// scores and flags of the records, the sources and their dates, and the
// names the map gives.
func TestBuildPinnedSnapshot(t *testing.T) {
	res, err := Build(pinned(t))
	if err != nil {
		t.Fatal(err)
	}
	m := res.Meta
	if m.Generator != advisory.IndexGenerator || m.Built != "2026-11-12" {
		t.Errorf("meta %+v", m)
	}
	if len(m.Sources) != 2 || m.Sources[0].Date != "2026-11-10" || m.Sources[0].N != 14 || m.Sources[1].N != 15 {
		t.Errorf("sources %+v, want KEV of 2026-11-10 with 14 and 15 NVD records", m.Sources)
	}
	// 15 records read; the Redis one has only a "-" version: nothing to index.
	if m.Records != 14 || m.Products < 11 || m.Entries < m.Records {
		t.Errorf("records %d products %d entries %d, want 14, at least 11 and at least 14", m.Records, m.Products, m.Entries)
	}
	httpd := product(res, "apache:http_server")
	v, ok := vuln(httpd, "CVE-2021-41773")
	if !ok || !v.KEV || v.CVSS != 9.8 || len(v.Ranges) != 0 || len(v.Versions) != 1 || v.Versions[0] != "2.4.49" || v.Cond != 0 {
		t.Errorf("CVE-2021-41773 %+v", v)
	}
	v, _ = vuln(httpd, "CVE-2019-0211")
	if len(v.Ranges) != 1 || v.Ranges[0] != "[2.4.17|2.4.38]" {
		t.Errorf("CVE-2019-0211 %+v, want the inclusive range", v)
	}
	// Not on KEV, and the configuration also names a platform.
	v, ok = vuln(httpd, "CVE-2010-0425")
	if !ok || v.KEV || v.Cond != advisory.CondPlatform || !slices.Contains(v.Ranges, "[2.0.37|2.0.64)") {
		t.Errorf("CVE-2010-0425 %+v", v)
	}
	// One range for each branch, and an open start.
	v, _ = vuln(product(res, "apache:tomcat"), "CVE-2020-1938")
	if len(v.Ranges) != 3 || !slices.Contains(v.Ranges, "[9.0.0|9.0.31)") {
		t.Errorf("CVE-2020-1938 %+v", v)
	}
	// An inclusive end with no start, and a start that is a branch.
	v, _ = vuln(product(res, "drupal:drupal"), "CVE-2018-7600")
	if len(v.Ranges) != 4 || !slices.Contains(v.Ranges, "[|7.57]") || !slices.Contains(v.Ranges, "[8.4.0|8.4.6)") {
		t.Errorf("CVE-2018-7600 %+v", v)
	}
	// Ranges for the long-term line and for the weekly one: conditional on which.
	v, _ = vuln(product(res, "jenkins:jenkins"), "CVE-2024-23897")
	if v.Cond != advisory.CondEdition || len(v.Ranges) != 2 {
		t.Errorf("CVE-2024-23897 %+v", v)
	}
	// "-" is no edition at all: MongoDB's ranges are not conditional.
	if v, _ = vuln(product(res, "mongodb:mongodb"), "CVE-2025-14847"); v.Cond != 0 || len(v.Ranges) != 6 {
		t.Errorf("CVE-2025-14847 %+v", v)
	}
	// A product with an escaped character in its name keeps it.
	if _, ok := vuln(product(res, "joomla:joomla!"), "CVE-2023-23752"); !ok {
		t.Error("joomla:joomla! has no CVE-2023-23752")
	}
	// The names: ProductKey of the map's name.
	if got := m.Names[advisory.ProductKey("Apache httpd")]; len(got) != 1 || got[0] != "apache:http_server" {
		t.Errorf("names of Apache httpd %v", got)
	}
	// KEV products no map line names are indexed under their own name.
	if len(res.Report.AutoProducts) == 0 {
		t.Error("no KEV product was indexed by its own CPE name")
	}
	if len(res.Report.NoRecords) != 1 || res.Report.NoRecords[0].CPE != "redis:redis" {
		t.Errorf("map lines with no record %+v, want redis alone", res.Report.NoRecords)
	}
	if len(res.Report.KEVMissing) != 0 {
		t.Errorf("KEV missing %v", res.Report.KEVMissing)
	}
}

// An index written and read again keeps its meta and its records.
func TestIndexRoundTrip(t *testing.T) {
	res, err := Build(pinned(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := advisory.WriteIndex(&buf, res.Meta, res.Products); err != nil {
		t.Fatal(err)
	}
	ix, err := advisory.ReadIndex(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if ix.Meta().Records != res.Meta.Records || ix.Meta().Label() != "advisory index 2026-11-12 (14 records)" {
		t.Errorf("meta %+v", ix.Meta())
	}
	meta, err := advisory.ReadIndexMeta(buf.Bytes())
	if err != nil || meta.Built != "2026-11-12" {
		t.Errorf("header %+v %v", meta, err)
	}
}

func feed(body string) []Feed { return []Feed{{Name: "t", R: strings.NewReader(body)}} }

func withFeed(t *testing.T, vulns string) (*Result, error) {
	o := pinned(t)
	o.Feeds = feed(`{"timestamp":"2026-11-11T00:00:00","vulnerabilities":[` + vulns + `]}`)
	return Build(o)
}

// A record the generator cannot read stops it; none is skipped.
func TestBuildFailsOnAMalformedRecord(t *testing.T) {
	cfg := func(criteria string, extra string) string {
		return `{"cve":{"id":"CVE-2021-0001","vulnStatus":"Analyzed","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"` + criteria + `"` + extra + `}]}]}]}}`
	}
	cases := map[string]string{
		"no id":                  `{"cve":{"vulnStatus":"Analyzed"}}`,
		"no cve":                 `{"id":"CVE-2021-0001"}`,
		"truncated":              `{"cve":{"id":"CVE-2021-0001","configurations":[`,
		"bad cpe":                cfg("cpe:2.3:a:apache:http_server:2.4.49", ""),
		"not a cpe":              cfg("apache http_server 2.4.49", ""),
		"empty product":          cfg("cpe:2.3:a:apache::2.4.49:*:*:*:*:*:*:*", ""),
		"version and range":      cfg("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", `,"versionEndExcluding":"2.4.50"`),
		"two bounds":             cfg("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", `,"versionEndExcluding":"2.4.50","versionEndIncluding":"2.4.49"`),
		"wildcard in a version":  cfg("cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*", ""),
		"a bound with the bar":   cfg("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", `,"versionEndExcluding":"2.4|50"`),
		"a CVE id that is not":   `{"cve":{"id":"GHSA-1","vulnStatus":"Analyzed"}}`,
		"a record that is a str": `"CVE-2021-0001"`,
	}
	for name, rec := range cases {
		if _, err := withFeed(t, rec); err == nil {
			t.Errorf("%s: the build went on", name)
		}
	}
	// The same record, well formed, builds.
	ok := cfg("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "")
	if _, err := withFeed(t, ok); err != nil {
		t.Errorf("a well formed record: %v", err)
	}
	if _, err := Build(Options{KEV: []byte(`{"count":2,"dateReleased":"2026-11-10T00:00:00Z","vulnerabilities":[{"cveID":"CVE-2021-0001"}]}`), Feeds: feed(`{"vulnerabilities":[]}`)}); err == nil {
		t.Error("a KEV catalogue whose count does not match its list was read")
	}
	if _, err := Build(Options{KEV: []byte(`{"count":1,"dateReleased":"2026-11-10T00:00:00Z","vulnerabilities":[{"cveID":"nope"}]}`), Feeds: feed(`{"vulnerabilities":[]}`)}); err == nil {
		t.Error("a KEV entry with no CVE id was read")
	}
	if _, err := Build(Options{KEV: []byte(`not json`), Feeds: feed(`{"vulnerabilities":[]}`)}); err == nil {
		t.Error("a KEV catalogue that is not JSON was read")
	}
	if _, err := Build(Options{KEV: read(t, "kev.json"), Feeds: feed(`{"timestamp":"x"}`)}); err == nil {
		t.Error("a feed with no vulnerabilities list was read")
	}
}

func TestParseMapFailsOnABadLine(t *testing.T) {
	for _, in := range []string{
		"Apache httpd\tapache:http_server",              // no source
		"Apache httpd\tapache\tservice",                 // not vendor:product
		"Apache httpd\tapache:http_server\tmagic",       // unknown source
		"Apache httpd\tapache:http_server\tkev",         // kev is no source a line names
		"A\ta:b\tservice\nA\ta:b\thand",                 // the same pair twice
		"\ta:b\tservice",                                // no name
		"Apache httpd\tapache:http_server:2.4\tservice", // a version
	} {
		if _, err := ParseMap(strings.NewReader(in)); err == nil {
			t.Errorf("%q read", in)
		}
	}
	got, err := ParseMap(strings.NewReader("# c\n\nA\ta:b\tservice\nA\tc:d\tservice\n"))
	if err != nil || len(got) != 2 {
		t.Errorf("%v %v", got, err)
	}
}

// The records the build leaves out are counted, never dropped quietly: a
// rejected record, one with no configuration yet, a version of "-".
func TestBuildCountsWhatItLeavesOut(t *testing.T) {
	res, err := withFeed(t, `
	  {"cve":{"id":"CVE-2021-0001","vulnStatus":"Rejected","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}]}},
	  {"cve":{"id":"CVE-2021-0002","vulnStatus":"Awaiting Analysis"}},
	  {"cve":{"id":"CVE-2021-0003","vulnStatus":"Analyzed","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*"},{"vulnerable":true,"criteria":"cpe:2.3:h:intel:*:*:*:*:*:*:*:*:*"},{"vulnerable":false,"criteria":"cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"}]}]}]}},
	  {"cve":{"id":"CVE-2021-0004","vulnStatus":"Analyzed","cisaExploitAdd":"2021-11-03","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.2:*:*:*:*:*:*:*"}]}]}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Report
	if r.FeedCVEs != 4 || r.Rejected != 1 || r.NoConfig != 1 || r.NotApplicable != 1 || r.NoProduct != 1 {
		t.Errorf("report %+v", r)
	}
	// NVD marks CVE-2021-0004 exploited and the KEV file does not list it.
	if len(r.KEVMismatch) != 1 || r.KEVMismatch[0] != "CVE-2021-0004" {
		t.Errorf("mismatch %v", r.KEVMismatch)
	}
	// Every KEV CVE of the file is missing from this feed, and said so.
	if len(r.KEVMissing) != 14 {
		t.Errorf("KEV missing %d, want 14", len(r.KEVMissing))
	}
	if _, ok := vuln(product(res, "apache:http_server"), "CVE-2021-0001"); ok {
		t.Error("a rejected record was indexed")
	}
}

// The score is the primary one of the newest CVSS version the record has;
// a record below the floor is kept only when it is on KEV.
func TestBuildScoreAndFloor(t *testing.T) {
	rec := func(id, metrics string) string {
		return `{"cve":{"id":"` + id + `","vulnStatus":"Analyzed","metrics":` + metrics + `,"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","versionEndExcluding":"2.4.1"}]}]}]}}`
	}
	o := pinned(t)
	o.Feeds = feed(`{"timestamp":"2026-11-11T00:00:00","vulnerabilities":[` +
		rec("CVE-2021-0010", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":9.0}}],"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":5.0}},{"type":"Primary","cvssData":{"baseScore":7.5}}]}`) + "," +
		rec("CVE-2021-0011", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":4.0}}]}`) + "," +
		rec("CVE-2021-41773", `{}`) + `]}`)
	o.MinCVSS = 7
	res, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	p := product(res, "apache:http_server")
	if v, ok := vuln(p, "CVE-2021-0010"); !ok || v.CVSS != 7.5 {
		t.Errorf("CVE-2021-0010 %+v, want 7.5 (the newest version's primary)", v)
	}
	if _, ok := vuln(p, "CVE-2021-0011"); ok {
		t.Error("a record below the floor and off KEV was kept")
	}
	if v, ok := vuln(p, "CVE-2021-41773"); !ok || !v.KEV {
		t.Errorf("a KEV record with no score was dropped: %+v", v)
	}
	if res.Report.DroppedByScope != 1 || !strings.Contains(res.Meta.Scope, "KEV") {
		t.Errorf("scope %q dropped %d", res.Meta.Scope, res.Report.DroppedByScope)
	}
}

// A name reaches the products of its best source only, and a name that a
// guessing source gives to two products reaches neither.
func TestBuildNamesTakeTheBestSource(t *testing.T) {
	rec := func(id, product string) string {
		return `{"cve":{"id":"` + id + `","vulnStatus":"Analyzed","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:` + product + `:1.0:*:*:*:*:*:*:*"}]}]}]}}`
	}
	o := pinned(t)
	o.Map = []MapLine{
		{"Thing", "guess:thing", SourceCPEDetect},
		{"Thing", "vendor:thing", SourceWappalyzer},
		{"Other", "a:other", SourceCPEDetect},
		{"Other", "b:other", SourceCPEDetect},
	}
	o.Feeds = feed(`{"timestamp":"2026-11-11T00:00:00","vulnerabilities":[` + rec("CVE-2021-0020", "guess:thing") + "," + rec("CVE-2021-0021", "vendor:thing") + "," +
		rec("CVE-2021-0022", "a:other") + "," + rec("CVE-2021-0023", "b:other") + `]}`)
	res, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Meta.Names[advisory.ProductKey("thing")]; len(got) != 1 || got[0] != "vendor:thing" {
		t.Errorf("thing %v, want the wappalyzer product only", got)
	}
	// Two products of one guessing source answer to "other": it reaches none.
	if got, ok := res.Meta.Names[advisory.ProductKey("other")]; ok {
		t.Errorf("other %v, want no product: two vendors answer to it", got)
	}
	if len(res.Report.AmbiguousNames) != 1 {
		t.Errorf("ambiguous names %v", res.Report.AmbiguousNames)
	}
}
