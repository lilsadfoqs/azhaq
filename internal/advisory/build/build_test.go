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
	if len(m.Sources) != 2 || m.Sources[0].Date != "2026-11-10" || m.Sources[0].N != 15 || m.Sources[1].N != 16 {
		t.Errorf("sources %+v, want KEV of 2026-11-10 with 15 and 16 NVD records", m.Sources)
	}
	// 15 records read; the Redis one has only a "-" version: nothing to index.
	if m.Records != 15 || m.Products < 12 || m.Entries < m.Records {
		t.Errorf("records %d products %d entries %d, want 15, at least 12 and at least 15", m.Records, m.Products, m.Entries)
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
	if !ok || v.KEV || v.Cond != advisory.CondPlatform || !slices.Contains(v.Ranges, "[2.0.37|2.0.64)") || len(v.Plat) == 0 {
		t.Errorf("CVE-2010-0425 %+v", v)
	}
	// A KEV record for OpenSSH that holds only where it runs on Alpine: the
	// platform is named, and the version 10.6 is listed beside the range.
	v, _ = vuln(product(res, "openbsd:openssh"), "CVE-2026-123158")
	if !v.KEV || v.Cond != advisory.CondPlatform || !slices.Equal(v.Plat, []string{"alpinelinux:alpine_linux"}) || !slices.Contains(v.Ranges, "[|10.6)") || !slices.Equal(v.Versions, []string{"10.6", "10.6-p1"}) {
		t.Errorf("CVE-2026-123158 %+v", v)
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
	if ix.Meta().Records != res.Meta.Records || ix.Meta().Label() != "advisory index 2026-11-12 (15 records)" {
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
	if len(r.KEVMissing) != 15 {
		t.Errorf("KEV missing %d, want 15", len(r.KEVMissing))
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

// The index carries a record's CVSS attack vector only when it is local or
// physical, read from the same metric the score is: the primary one of the
// newest CVSS version. Network and adjacent records carry none.
func TestBuildKeepsTheAttackVectorThatTheNetworkDoesNotReach(t *testing.T) {
	m := func(list, typ, ver, vec string) string {
		return `"` + list + `":[{"type":"` + typ + `","cvssData":{"version":"` + ver + `","vectorString":"` + vec + `","baseScore":7.0}}]`
	}
	rec := func(id, metrics string) string {
		return `{"cve":{"id":"` + id + `","vulnStatus":"Analyzed","metrics":{` + metrics + `},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","versionEndExcluding":"2.4.1"}]}]}]}}`
	}
	res, err := withFeed(t, strings.Join([]string{
		rec("CVE-2021-0040", m("cvssMetricV31", "Primary", "3.1", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")),
		rec("CVE-2021-0041", m("cvssMetricV40", "Primary", "4.0", "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")),
		rec("CVE-2021-0042", m("cvssMetricV2", "Primary", "2.0", "AV:L/AC:L/Au:N/C:P/I:P/A:P")),
		rec("CVE-2021-0043", m("cvssMetricV31", "Primary", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
		rec("CVE-2021-0044", m("cvssMetricV30", "Primary", "3.0", "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
		rec("CVE-2021-0045", ``),
		// The primary metric of the version wins over a secondary one that says otherwise.
		rec("CVE-2021-0046", `"cvssMetricV31":[{"type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":7.0}},{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}]`),
		// The newest version wins, as the score does.
		rec("CVE-2021-0047", m("cvssMetricV40", "Primary", "4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")+","+m("cvssMetricV31", "Primary", "3.1", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")),
	}, ","))
	if err != nil {
		t.Fatal(err)
	}
	p := product(res, "apache:http_server")
	for id, want := range map[string]string{
		"CVE-2021-0040": advisory.AVLocal, "CVE-2021-0041": advisory.AVPhysical, "CVE-2021-0042": advisory.AVLocal,
		"CVE-2021-0043": "", "CVE-2021-0044": "", "CVE-2021-0045": "", "CVE-2021-0046": "", "CVE-2021-0047": "",
	} {
		if v, ok := vuln(p, id); !ok || v.AV != want {
			t.Errorf("%s: attack vector %q, want %q", id, v.AV, want)
		}
	}
	r := res.Report
	if r.AttackVectors["L"] != 2 || r.AttackVectors["P"] != 1 || r.AttackVectors["N"] != 3 || r.AttackVectors["A"] != 1 || r.NoVector != 1 {
		t.Errorf("vectors %v, none %d", r.AttackVectors, r.NoVector)
	}
	if r.VectorVersions["2.0"] != 1 || r.VectorVersions["3.0"] != 1 || r.VectorVersions["3.1"] != 3 || r.VectorVersions["4.0"] != 2 {
		t.Errorf("vector versions %v", r.VectorVersions)
	}
}

// Built twice from the same records, the index is the same bytes, vectors included.
func TestBuildIsReproducible(t *testing.T) {
	write := func() []byte {
		res, err := Build(pinned(t))
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := advisory.WriteIndex(&b, res.Meta, res.Products); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	if !bytes.Equal(write(), write()) {
		t.Error("two builds of the same records differ")
	}
}

// A vector string that does not read stops the build.
func TestBuildFailsOnAVectorItCannotRead(t *testing.T) {
	for name, vec := range map[string]string{"no attack vector": "CVSS:3.1/AC:L/PR:N", "an unknown one": "CVSS:3.1/AV:X/AC:L", "a long one": "CVSS:3.1/AV:NL/AC:L"} {
		_, err := withFeed(t, `{"cve":{"id":"CVE-2021-0050","vulnStatus":"Analyzed","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"`+vec+`","baseScore":5.0}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"}]}]}]}}`)
		if err == nil || !strings.Contains(err.Error(), "CVE-2021-0050") {
			t.Errorf("%s: err %v", name, err)
		}
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

// A record whose own CNA names another product than the one it is filed
// under keeps that name; a record whose CNA names the product, names it under
// another spelling, or names nothing ("n/a") keeps none, and another source's
// list of affected products is not the record's own.
func TestBuildKeepsTheComponentTheCNANames(t *testing.T) {
	rec := func(id, aff string) string {
		return `{"cve":{"id":"` + id + `","sourceIdentifier":"cna@curl.se","vulnStatus":"Analyzed","affected":[` + aff + `],"configurations":[{"nodes":[{"cpeMatch":[` +
			`{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"},` +
			`{"vulnerable":true,"criteria":"cpe:2.3:a:mongodb:mongodb:4.0.0:*:*:*:*:*:*:*"}]}]}]}}`
	}
	data := func(source, vendor, product string) string {
		return `{"source":"` + source + `","affectedData":[{"vendor":"` + vendor + `","product":"` + product + `","versions":[{"version":"n/a","status":"affected"}]}]}`
	}
	res, err := withFeed(t, strings.Join([]string{
		rec("CVE-2021-0030", data("cna@curl.se", "curl", "libcurl")),
		rec("CVE-2021-0031", data("cna@curl.se", "n/a", "n/a")),
		rec("CVE-2021-0032", data("cna@curl.se", "Apache Software Foundation", "Apache HTTP Server")+","+data("cna@curl.se", "curl", "libcurl")),
		rec("CVE-2021-0033", data("someone@else.org", "curl", "libcurl")),
		rec("CVE-2021-0034", ""),
	}, ","))
	if err != nil {
		t.Fatal(err)
	}
	httpd, mongo := product(res, "apache:http_server"), product(res, "mongodb:mongodb")
	for id, want := range map[string][]string{
		"CVE-2021-0030": {"libcurl"}, // another product than either of the two it is filed under
		"CVE-2021-0031": nil,         // n/a says nothing
		"CVE-2021-0033": nil,         // not the record's own CNA
		"CVE-2021-0034": nil,         // no statement at all
	} {
		for _, p := range []advisory.IndexProduct{httpd, mongo} {
			if v, ok := vuln(p, id); !ok || !slices.Equal(v.Comp, want) {
				t.Errorf("%s under %s: component %v, want %v", id, p.CPE, v.Comp, want)
			}
		}
	}
	// The CNA names httpd and libcurl: it is httpd's own record, and mongodb's is not.
	if v, _ := vuln(httpd, "CVE-2021-0032"); len(v.Comp) != 0 {
		t.Errorf("a record that names the product: %v", v.Comp)
	}
	if v, _ := vuln(mongo, "CVE-2021-0032"); !slices.Equal(v.Comp, []string{"Apache HTTP Server", "libcurl"}) {
		t.Errorf("mongodb under a record of httpd and libcurl: %v", v.Comp)
	}
}

func TestNamesProduct(t *testing.T) {
	for _, c := range []struct {
		name, vendor, product string
		want                  bool
	}{
		{"MySQL Server", "oracle", "mysql_server", true},
		{"Apache HTTP Server", "apache", "http_server", true},
		{"OpenSSH", "openbsd", "openssh", true},
		{"BIG-IP", "f5", "big-ip_access_policy_manager", true},
		{"Advantech", "advantech", "r-seenet", true}, // the vendor alone says nothing of the product
		{"MySQL Server", "mariadb", "mariadb", false},
		{"libcurl", "oracle", "mysql_server", false},
		{"Apache Log4j2", "cisco", "finesse", false},
		{"xstream", "apache", "activemq", false},
	} {
		if got := namesProduct(c.name, c.vendor, c.product); got != c.want {
			t.Errorf("%q for %s:%s: %v, want %v", c.name, c.vendor, c.product, got, c.want)
		}
	}
}

// A name of generic words alone ("server", "core") names no product, and a
// name whose words are all the vendor's or the product's is the product.
func TestGenericNamesNameNoComponent(t *testing.T) {
	for _, c := range []struct {
		name, vendor, product string
		comp                  bool
	}{
		{"server", "mariadb", "mariadb", false},
		{"Core", "dnn", "dnn", false},
		{"XI", "nagios", "nagios_xi", false},
		{"n/a", "x", "y", false},
		{"Red Hat Enterprise Linux 9", "openbsd", "openssh", false}, // a distribution is what it is packaged in
		{"Windows SMB", "samba", "samba", false},
		{"libcurl", "mariadb", "mariadb", true},
	} {
		got := otherComponent(cnaProducts(nvdCVE{SourceID: "s", Affected: []nvdAffected{{Source: "s", Data: []struct {
			Vendor  string `json:"vendor"`
			Product string `json:"product"`
		}{{Product: c.name}}}}}), c.vendor, c.product)
		if (len(got) > 0) != c.comp {
			t.Errorf("%q for %s:%s: %v", c.name, c.vendor, c.product, got)
		}
	}
}
