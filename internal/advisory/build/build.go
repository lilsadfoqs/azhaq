// Package build makes the advisory index from public records: the CISA
// KEV catalogue and the NVD CVE records (feed format 2.0, with their CPE
// configurations). It does no network I/O of its own: scripts/advindex
// fetches the records and calls Build. A record it cannot read is an
// error, never skipped.
package build

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

// Tiers say how a product name came to be in the map: a name a person
// wrote for a service azhaq names, or one from a detection catalogue.
// When one name maps to products of different tiers, the best tier wins.
const (
	SourceService    = "service"    // a product azhaq names on the wire (a banner, a Server header)
	SourceHand       = "hand"       // added by hand, from a product azhaq's catalogues name
	SourceWappalyzer = "wappalyzer" // the CPE of a wappalyzer fingerprint
	SourceCPEDetect  = "cpedetect"  // the vendor and product of a cpedetect query
	sourceAuto       = "kev"        // a KEV product no catalogue names: its own CPE product name
)

var tier = map[string]int{SourceService: 1, SourceHand: 1, SourceWappalyzer: 2, SourceCPEDetect: 3, sourceAuto: 4}

// MapLine is one line of the product map: a name azhaq reports, the NVD
// CPE vendor:product it is, and where the name comes from.
type MapLine struct {
	Name, CPE, Source string
}

// ParseMap reads the product map: name TAB vendor:product TAB source, one
// product a line; # starts a comment. A malformed line, an unknown source
// or a repeated pair is an error.
func ParseMap(r io.Reader) ([]MapLine, error) {
	var out []MapLine
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("product map line %d: want name, vendor:product and source separated by tabs", n)
		}
		m := MapLine{Name: strings.TrimSpace(f[0]), CPE: strings.TrimSpace(f[1]), Source: strings.TrimSpace(f[2])}
		if m.Name == "" || strings.Count(m.CPE, ":") != 1 || strings.HasPrefix(m.CPE, ":") || strings.HasSuffix(m.CPE, ":") || strings.ContainsAny(m.CPE, " *") {
			return nil, fmt.Errorf("product map line %d: %q is not a name and an NVD vendor:product", n, line)
		}
		if tier[m.Source] == 0 || m.Source == sourceAuto {
			return nil, fmt.Errorf("product map line %d: unknown source %q", n, m.Source)
		}
		if k := m.Name + "\x00" + m.CPE; seen[k] {
			return nil, fmt.Errorf("product map line %d: %q is mapped to %s twice", n, m.Name, m.CPE)
		} else {
			seen[k] = true
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Feed is one NVD CVE feed (nvdcve-2.0-YYYY.json), already decompressed.
type Feed struct {
	Name string
	R    io.Reader
}

// Options are the inputs of Build.
type Options struct {
	KEV     []byte // the CISA KEV JSON
	KEVURL  string
	NVDURL  string
	Feeds   []Feed
	Map     []MapLine
	Built   string  // the day it is built (YYYY-MM-DD)
	MinCVSS float64 // 0: keep every record; else keep a record below it only when it is on KEV
}

// Report is what Build saw that the caller should say.
type Report struct {
	FeedCVEs       int      // CVE records read from the feeds
	Rejected       int      // records NVD marks rejected: not indexed
	NoConfig       int      // records with no CPE configuration yet: nothing to match, not indexed
	NotApplicable  int      // CPE matches whose version is "-" (not applicable): not indexed
	NoProduct      int      // CPE matches that name no one product (vendor or product "*"): not indexed
	KEVMissing     []string // KEV CVEs no feed holds
	KEVNoProduct   []string // KEV CVEs held, with no application or OS product to index
	KEVMismatch    []string // CVEs NVD marks as exploited that the KEV file does not list
	NoRecords      []MapLine
	AutoProducts   []string // KEV products no map line names, indexed under their CPE name
	DroppedByScope int
	AmbiguousNames []string // names left out because two products of a catalogue's guess answer to them
	// What the indexed records state as their CVSS attack vector: how many
	// for each letter (N, A, L, P), how many from each CVSS version, and how
	// many state none.
	AttackVectors  map[string]int
	VectorVersions map[string]int
	NoVector       int
}

// Result is a built index and its report.
type Result struct {
	Meta     advisory.IndexMeta
	Products []advisory.IndexProduct
	Report   Report
}

type kevFile struct {
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVE     string `json:"cveID"`
		Vendor  string `json:"vendorProject"`
		Product string `json:"product"`
	} `json:"vulnerabilities"`
}

// ParseKEV reads the KEV JSON: the day it was released and the CVE ids.
func ParseKEV(raw []byte) (date string, ids map[string]bool, err error) {
	var k kevFile
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", nil, fmt.Errorf("the KEV catalogue: %w", err)
	}
	if len(k.Vulnerabilities) == 0 {
		return "", nil, fmt.Errorf("the KEV catalogue holds no vulnerabilities")
	}
	if k.Count != len(k.Vulnerabilities) {
		return "", nil, fmt.Errorf("the KEV catalogue says %d vulnerabilities and holds %d", k.Count, len(k.Vulnerabilities))
	}
	ids = map[string]bool{}
	for i, v := range k.Vulnerabilities {
		if !validCVE(v.CVE) {
			return "", nil, fmt.Errorf("the KEV catalogue: entry %d has no valid cveID (%q)", i, v.CVE)
		}
		ids[v.CVE] = true
	}
	if len(k.DateReleased) < 10 {
		return "", nil, fmt.Errorf("the KEV catalogue has no dateReleased")
	}
	return k.DateReleased[:10], ids, nil
}

func validCVE(id string) bool {
	if !strings.HasPrefix(id, "CVE-") || strings.Count(id, "-") != 2 {
		return false
	}
	for _, r := range strings.ReplaceAll(id[4:], "-", "") {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// The NVD 2.0 feed fields Build reads.
type nvdCVE struct {
	ID             string        `json:"id"`
	SourceID       string        `json:"sourceIdentifier"`
	VulnStatus     string        `json:"vulnStatus"`
	CisaExploitAdd string        `json:"cisaExploitAdd"`
	Metrics        nvdMetrics    `json:"metrics"`
	Configurations []nvdConfig   `json:"configurations"`
	Affected       []nvdAffected `json:"affected"`
}

// nvdAffected is what one source says the record's flaw affects: the CNA's
// own statement is the one whose source is the record's sourceIdentifier.
type nvdAffected struct {
	Source string `json:"source"`
	Data   []struct {
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
	} `json:"affectedData"`
}

// cnaProducts are the products the record's own CNA names as affected
// (an empty name, "n/a" and a name of generic words alone say nothing).
func cnaProducts(c nvdCVE) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range c.Affected {
		if a.Source != c.SourceID {
			continue
		}
		for _, d := range a.Data {
			p := strings.TrimSpace(d.Product)
			if !distinguishing(p) || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// genericWords are words of a product name that name no product: a name made
// of them alone ("server", "core", "platform") is the vendor's, whatever the
// product, and says nothing of which one.
var genericWords = map[string]bool{
	"server": true, "client": true, "manager": true, "plugin": true, "enterprise": true, "edition": true,
	"application": true, "cloud": true, "portal": true, "console": true, "gateway": true, "service": true,
	"services": true, "system": true, "data": true, "management": true, "network": true, "software": true,
	"platform": true, "product": true, "products": true, "multiple": true, "tools": true, "security": true,
	"access": true, "web": true, "project": true, "foundation": true, "corporation": true,
	"core": true, "cms": true, "api": true, "app": true, "suite": true, "framework": true, "library": true,
	"engine": true, "pro": true, "lite": true, "free": true, "plus": true,
}

func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') })
}

func alnum(s string) string { return strings.Join(words(s), "") }

// osNames are the first words of a name that is an operating system or a
// distribution: what a product runs on or is packaged in, not a component of
// it (a distribution's own record of its package names the distribution).
var osNames = map[string]bool{
	"red": true, "redhat": true, "rhel": true, "suse": true, "sles": true, "opensuse": true, "ubuntu": true,
	"debian": true, "fedora": true, "centos": true, "alpine": true, "amazon": true, "rocky": true, "almalinux": true,
	"windows": true, "macos": true, "mac": true, "ios": true, "ipados": true, "tvos": true, "watchos": true,
	"android": true, "linux": true, "freebsd": true, "openbsd": true, "netbsd": true, "solaris": true,
}

// distinguishing says a name names a product: it has a word that is not a
// generic one, and it is not an operating system or a distribution.
func distinguishing(name string) bool {
	if alnum(name) == "na" {
		return false
	}
	if w := words(name); len(w) > 0 && osNames[w[0]] {
		return false
	}
	for _, w := range words(name) {
		if !genericWords[w] {
			return true
		}
	}
	return false
}

// namesProduct says a name the CNA gave is the CPE product vendor:product:
// the product's own name, one that holds it or is held by it, one made of
// words of the vendor and the product, one that shares a word of it, or only
// the vendor's.
func namesProduct(name, vendor, product string) bool {
	a, b := alnum(product), alnum(name)
	if len(a) >= 3 && len(b) >= 3 && (strings.Contains(a, b) || strings.Contains(b, a)) {
		return true
	}
	if b == alnum(vendor) {
		return true
	}
	have := map[string]bool{}
	for _, w := range append(words(vendor), words(product)...) {
		have[w] = true
	}
	all := true
	for _, w := range words(name) {
		if len(w) >= 4 && !genericWords[w] && have[w] {
			return true
		}
		all = all && have[w]
	}
	return all
}

// otherComponent is the products the record's CNA names when none of them
// is the CPE product (at most two, kept short): the record says the flaw is
// in something else than the product it was filed under. None when the CNA
// named nothing, which is the case of most records before 2018.
func otherComponent(names []string, vendor, product string) []string {
	if len(names) == 0 {
		return nil
	}
	for _, n := range names {
		if namesProduct(n, vendor, product) {
			return nil
		}
	}
	var out []string
	for _, n := range names {
		if len(out) == 2 {
			break
		}
		out = append(out, string([]rune(n)[:min(len([]rune(n)), 48)]))
	}
	return out
}

type nvdMetrics struct {
	V31 []nvdMetric `json:"cvssMetricV31"`
	V40 []nvdMetric `json:"cvssMetricV40"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string   `json:"version"`
		VectorString string   `json:"vectorString"`
		BaseScore    *float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type nvdConfig struct {
	Operator string    `json:"operator"`
	Nodes    []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	Match    []nvdMatch `json:"cpeMatch"`
}

type nvdMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
	StartIncl  string `json:"versionStartIncluding"`
	StartExcl  string `json:"versionStartExcluding"`
	EndIncl    string `json:"versionEndIncluding"`
	EndExcl    string `json:"versionEndExcluding"`
}

// pick is the metric a record's score and attack vector are read from: the
// primary one of the newest CVSS version that has a score, else the first of
// that version. One metric for both, so they never come from two versions.
func (m nvdMetrics) pick() *nvdMetric {
	for _, list := range [][]nvdMetric{m.V40, m.V31, m.V30, m.V2} {
		var first *nvdMetric
		for i, x := range list {
			if x.CVSSData.BaseScore == nil {
				continue
			}
			if x.Type == "Primary" {
				return &list[i]
			}
			if first == nil {
				first = &list[i]
			}
		}
		if first != nil {
			return first
		}
	}
	return nil
}

// score is the base score a record states.
func (m nvdMetrics) score() float64 {
	if x := m.pick(); x != nil {
		return *x.CVSSData.BaseScore
	}
	return 0
}

// vector is the CVSS version and the attack vector letter (N network, A
// adjacent, L local, P physical) of the record's metric. It is empty when
// the record has no metric or its metric states no vector; a vector string
// that does not read is an error, like any record azhaq cannot read.
func (m nvdMetrics) vector() (version, av string, err error) {
	x := m.pick()
	if x == nil || x.CVSSData.VectorString == "" {
		return "", "", nil
	}
	vs := x.CVSSData.VectorString
	for _, f := range strings.Split(vs, "/") {
		if v, ok := strings.CutPrefix(f, "AV:"); ok {
			if len(v) != 1 || !strings.Contains("NALP", v) {
				return "", "", fmt.Errorf("CVSS vector %q: attack vector %q", vs, v)
			}
			return x.CVSSData.Version, v, nil
		}
	}
	return "", "", fmt.Errorf("CVSS vector %q has no attack vector", vs)
}

// SplitCPE splits a CPE 2.3 formatted string into its 13 fields, taking
// the escaped colon (\:) as part of a field.
func SplitCPE(s string) ([]string, error) {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		case c == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	fields = append(fields, cur.String())
	if len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
		return nil, fmt.Errorf("%q is not a CPE 2.3 string", s)
	}
	return fields, nil
}

// entry is what is collected for one (product, CVE).
type entry struct {
	ranges   map[string]bool
	versions map[string]bool
	platform bool            // every configuration that names the product also names a platform
	editions map[string]bool // the editions and targets the matches name ("" for none)
	plats    map[string]bool // what the configurations say the product runs on or with (vendor:product)
	comp     []string        // what the record's CNA names when it is not this product
}

// siblings are the products of a configuration that stand beside the node
// ni (a platform the product runs on, a component it needs), and, within an
// AND node, the other products of the node: what the version alone does not show.
func siblings(cfg nvdConfig, ni int, own string) map[string]bool {
	out := map[string]bool{}
	add := func(m nvdMatch) {
		if f, err := SplitCPE(m.Criteria); err == nil && f[3] != "" && f[4] != "" && f[3] != "*" && f[4] != "*" && f[3]+":"+f[4] != own {
			out[f[3]+":"+f[4]] = true
		}
	}
	if cfg.Operator == "AND" {
		for j, n := range cfg.Nodes {
			if j != ni {
				for _, m := range n.Match {
					add(m)
				}
			}
		}
	}
	if n := cfg.Nodes[ni]; n.Operator == "AND" {
		for _, m := range n.Match {
			add(m)
		}
	}
	return out
}

type acc struct {
	byProduct map[string]map[string]*entry // cpe → CVE → entry
	cvss      map[string]float64
	av        map[string]string // CVE → attack vector letter, when the record states one
	avVersion map[string]string // CVE → the CVSS version that vector is of
	kev       map[string]bool
	seenKEV   map[string]bool
	noProduct map[string]bool
}

// Build makes the index.
func Build(o Options) (*Result, error) {
	kevDate, kevIDs, err := ParseKEV(o.KEV)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, m := range o.Map {
		wanted[m.CPE] = true
	}
	a := &acc{byProduct: map[string]map[string]*entry{}, cvss: map[string]float64{}, av: map[string]string{}, avVersion: map[string]string{}, kev: kevIDs, seenKEV: map[string]bool{}, noProduct: map[string]bool{}}
	rep := Report{}
	nvdDate := ""
	for _, f := range o.Feeds {
		ts, err := readFeed(f, func(c nvdCVE) error { return a.add(c, wanted, &rep) })
		if err != nil {
			return nil, fmt.Errorf("feed %s: %w", f.Name, err)
		}
		if len(ts) >= 10 && ts[:10] > nvdDate {
			nvdDate = ts[:10]
		}
	}
	if rep.FeedCVEs == 0 {
		return nil, fmt.Errorf("the NVD feeds hold no CVE record")
	}
	for id := range kevIDs {
		if !a.seenKEV[id] {
			rep.KEVMissing = append(rep.KEVMissing, id)
		} else if a.noProduct[id] {
			rep.KEVNoProduct = append(rep.KEVNoProduct, id)
		}
	}
	sort.Strings(rep.KEVMissing)
	sort.Strings(rep.KEVNoProduct)
	sort.Strings(rep.KEVMismatch)

	meta := advisory.IndexMeta{Generator: advisory.IndexGenerator, Built: o.Built, Names: map[string][]string{}}
	var products []advisory.IndexProduct
	ids := map[string]bool{}
	for cpe, byCVE := range a.byProduct {
		p := advisory.IndexProduct{CPE: cpe}
		for id, e := range byCVE {
			v := advisory.IndexVuln{ID: id, CVSS: a.cvss[id], KEV: kevIDs[id]}
			// Only a flaw that cannot be reached over the network is kept: a
			// network or adjacent one is the rule and needs no mark.
			if av := a.av[id]; av == advisory.AVLocal || av == advisory.AVPhysical {
				v.AV = av
			}
			if e.platform {
				v.Cond |= advisory.CondPlatform
				// The first few of what it runs on, so a lead can name them.
				v.Plat = keys(e.plats)
				if len(v.Plat) > 4 {
					v.Plat = v.Plat[:4]
				}
			}
			// Ranges for several editions or targets (a long-term release
			// line and the weekly one), or for one named edition: the version
			// azhaq reads does not say which the service is.
			if len(e.editions) > 1 || (len(e.editions) == 1 && !e.editions[""]) {
				v.Cond |= advisory.CondEdition
			}
			if o.MinCVSS > 0 && !v.KEV && v.CVSS < o.MinCVSS {
				rep.DroppedByScope++
				continue
			}
			v.Ranges, v.Versions, v.Comp = keys(e.ranges), keys(e.versions), e.comp
			p.Vulns = append(p.Vulns, v)
			ids[id] = true
		}
		if len(p.Vulns) > 0 {
			products = append(products, p)
			meta.Entries += len(p.Vulns)
		}
	}
	have := map[string]bool{}
	for _, p := range products {
		have[p.CPE] = true
	}
	names := map[string]map[int]map[string]bool{} // ProductKey → tier → cpe
	addName := func(name, cpe string, t int) {
		k := advisory.ProductKey(name)
		if k == "" {
			return
		}
		if names[k] == nil {
			names[k] = map[int]map[string]bool{}
		}
		if names[k][t] == nil {
			names[k][t] = map[string]bool{}
		}
		names[k][t][cpe] = true
	}
	for _, m := range o.Map {
		if !have[m.CPE] {
			rep.NoRecords = append(rep.NoRecords, m)
			continue
		}
		addName(m.Name, m.CPE, tier[m.Source])
	}
	for _, p := range products {
		if !wanted[p.CPE] {
			rep.AutoProducts = append(rep.AutoProducts, p.CPE)
			if n := autoName(p.CPE); n != "" {
				addName(n, p.CPE, tier[sourceAuto])
			}
		}
	}
	sort.Strings(rep.AutoProducts)
	for k, byTier := range names {
		best := 99
		for t := range byTier {
			if t < best {
				best = t
			}
		}
		// A name only a catalogue's guess or a KEV product's own name gives,
		// and that two products answer to, is not told apart: it reaches none.
		if best >= tier[SourceCPEDetect] && len(byTier[best]) > 1 {
			rep.AmbiguousNames = append(rep.AmbiguousNames, k)
			continue
		}
		meta.Names[k] = keys(byTier[best])
	}
	sort.Strings(rep.AmbiguousNames)
	// A product no name reaches is still kept: its records were asked for
	// (a KEV record) and a user's -advisory-source cannot reach it, but a
	// later map line can.
	meta.Records, meta.Products = len(ids), len(products)
	rep.AttackVectors, rep.VectorVersions = map[string]int{}, map[string]int{}
	for id := range ids {
		if av := a.av[id]; av != "" {
			rep.AttackVectors[av]++
			rep.VectorVersions[a.avVersion[id]]++
		} else {
			rep.NoVector++
		}
	}
	meta.Sources = []advisory.IndexSource{
		{Name: "CISA Known Exploited Vulnerabilities catalogue", URL: o.KEVURL, Date: kevDate, N: len(kevIDs)},
		{Name: "NVD CVE records, feed 2.0 (with CPE configurations)", URL: o.NVDURL, Date: nvdDate, N: rep.FeedCVEs},
	}
	if o.MinCVSS > 0 {
		meta.Scope = fmt.Sprintf("every record on the CISA KEV catalogue, and the records of CVSS %.1f and above", o.MinCVSS)
	}
	return &Result{Meta: meta, Products: products, Report: rep}, nil
}

// genericNames are CPE product names too general to be a name azhaq's
// services reach on their own: a service called "HTTP Server" is not
// every vendor's http_server.
var genericNames = map[string]bool{
	"httpserver": true, "http": true, "server": true, "webserver": true, "client": true,
	"agent": true, "console": true, "manager": true, "portal": true, "gateway": true,
	"firmware": true, "windows": true, "linux": true, "kernel": true, "framework": true,
	"api": true, "app": true, "application": true, "web": true, "proxy": true, "router": true,
}

// autoName is the name a CPE product is reached by when no map line
// names it: its own product part, unless it is too short or too general.
func autoName(cpe string) string {
	_, product, _ := strings.Cut(cpe, ":")
	k := advisory.ProductKey(product)
	if len(k) < 3 || genericNames[k] {
		return ""
	}
	return product
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readFeed streams the vulnerabilities of one NVD 2.0 feed and returns
// the feed's timestamp.
func readFeed(f Feed, each func(nvdCVE) error) (timestamp string, err error) {
	dec := json.NewDecoder(f.R)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", fmt.Errorf("not an NVD feed: no top-level object")
	}
	got := false
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", err
		}
		key, _ := t.(string)
		switch key {
		case "vulnerabilities":
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				return "", fmt.Errorf("vulnerabilities is not a list")
			}
			got = true
			for dec.More() {
				var v struct {
					CVE *nvdCVE `json:"cve"`
				}
				if err := dec.Decode(&v); err != nil {
					return "", fmt.Errorf("a vulnerability record: %w", err)
				}
				if v.CVE == nil {
					return "", fmt.Errorf("a vulnerability record has no cve")
				}
				if err := each(*v.CVE); err != nil {
					return "", err
				}
			}
			if _, err := dec.Token(); err != nil {
				return "", err
			}
		case "timestamp":
			if err := dec.Decode(&timestamp); err != nil {
				return "", err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", err
			}
		}
	}
	if !got {
		return "", fmt.Errorf("not an NVD feed: no vulnerabilities list")
	}
	return timestamp, nil
}

func (a *acc) add(c nvdCVE, wanted map[string]bool, rep *Report) error {
	rep.FeedCVEs++
	if !validCVE(c.ID) {
		return fmt.Errorf("a record has no valid CVE id (%q)", c.ID)
	}
	isKEV := a.kev[c.ID]
	if isKEV {
		a.seenKEV[c.ID] = true
	} else if c.CisaExploitAdd != "" {
		rep.KEVMismatch = append(rep.KEVMismatch, c.ID)
	}
	if c.VulnStatus == "Rejected" {
		rep.Rejected++
		return nil
	}
	if len(c.Configurations) == 0 {
		rep.NoConfig++
		return nil
	}
	kept := 0
	cna := cnaProducts(c)
	for _, cfg := range c.Configurations {
		cond := cfg.Operator == "AND" && len(cfg.Nodes) > 1
		for ni, n := range cfg.Nodes {
			if n.Negate {
				continue
			}
			nodeCond := cond || (n.Operator == "AND" && len(n.Match) > 1)
			for _, m := range n.Match {
				if !m.Vulnerable {
					continue
				}
				f, err := SplitCPE(m.Criteria)
				if err != nil {
					return fmt.Errorf("%s: %w", c.ID, err)
				}
				part, vendor, product, ver, upd := f[2], f[3], f[4], f[5], f[6]
				edition := strings.Join(f[7:], ":") // edition, language, sw_edition, target_sw, target_hw, other
				edition = strings.Trim(strings.NewReplacer("*", "", "-", "").Replace(edition), ":")
				if vendor == "" || product == "" {
					return fmt.Errorf("%s: CPE %q names no vendor or product", c.ID, m.Criteria)
				}
				if vendor == "*" || product == "*" || vendor == "-" || product == "-" {
					rep.NoProduct++ // every product of a vendor, or none named: nothing to key a lookup on
					continue
				}
				key := vendor + ":" + product
				if !wanted[key] && !(isKEV && (part == "a" || part == "o")) {
					continue
				}
				rng, exact, na, err := versionOf(m, ver, upd)
				if err != nil {
					return fmt.Errorf("%s: %w", c.ID, err)
				}
				if na {
					rep.NotApplicable++
					continue
				}
				byCVE := a.byProduct[key]
				if byCVE == nil {
					byCVE = map[string]*entry{}
					a.byProduct[key] = byCVE
				}
				e := byCVE[c.ID]
				if e == nil {
					e = &entry{ranges: map[string]bool{}, versions: map[string]bool{}, platform: true, editions: map[string]bool{}, plats: map[string]bool{},
						comp: otherComponent(cna, vendor, product)}
					byCVE[c.ID] = e
				}
				// A record is conditional on a platform only when every
				// configuration that names the product also names one.
				e.platform = e.platform && nodeCond
				if nodeCond {
					for k := range siblings(cfg, ni, key) {
						e.plats[k] = true
					}
				}
				e.editions[edition] = true
				if rng != "" {
					e.ranges[rng] = true
				} else {
					e.versions[exact] = true
				}
				kept++
			}
		}
	}
	if kept == 0 && isKEV {
		a.noProduct[c.ID] = true
	}
	if kept > 0 {
		a.cvss[c.ID] = c.Metrics.score()
		ver, av, err := c.Metrics.vector()
		if err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
		a.av[c.ID], a.avVersion[c.ID] = av, ver
	}
	return nil
}

// versionOf is the version part of a vulnerable CPE match: a range of the
// index, or one exact version. na says the match names no version ("-").
func versionOf(m nvdMatch, ver, upd string) (rng, exact string, na bool, err error) {
	hasRange := m.StartIncl != "" || m.StartExcl != "" || m.EndIncl != "" || m.EndExcl != ""
	switch {
	case hasRange:
		if ver != "*" {
			return "", "", false, fmt.Errorf("CPE %q has a version and a range", m.Criteria)
		}
		if m.StartIncl != "" && m.StartExcl != "" || m.EndIncl != "" && m.EndExcl != "" {
			return "", "", false, fmt.Errorf("CPE %q has two bounds on one end", m.Criteria)
		}
		start, startIncl := m.StartIncl, true
		if m.StartExcl != "" {
			start, startIncl = m.StartExcl, false
		}
		end, endIncl := m.EndExcl, false
		if m.EndIncl != "" {
			end, endIncl = m.EndIncl, true
		}
		if strings.Contains(start+end, "|") {
			return "", "", false, fmt.Errorf("CPE %q has a bound azhaq cannot write as a range (%q, %q)", m.Criteria, start, end)
		}
		return advisory.FormatIndexRange(start, startIncl, end, endIncl), "", false, nil
	case ver == "*":
		return advisory.FormatIndexRange("", true, "", false), "", false, nil
	case ver == "-":
		return "", "", true, nil
	case ver == "" || strings.ContainsAny(ver, "*?"):
		return "", "", false, fmt.Errorf("CPE %q has a version azhaq cannot read (%q)", m.Criteria, ver)
	}
	if upd != "" && upd != "*" && upd != "-" {
		ver += "-" + upd
	}
	return "", ver, false, nil
}
