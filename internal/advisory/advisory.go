// Package advisory matches a product and version azhaq already confirmed
// against public advisory records (the built-in index, and OSV JSON the user
// gives), and, only when asked, reads
// one benign signal a service already exposes to say how far that match
// is confirmed. It never sends a payload, never logs in, never changes
// state and never tries to trigger an issue: a version-range match is a
// labelled lead, never a proven, exploitable finding.
//
// Data sources: the index azhaq carries (index.go, built by hand with
// `go run ./scripts/advindex` from the CISA KEV catalogue and the NVD
// records, and embedded), and the OSV records of the user's
// -advisory-source, a file (works offline) or a URL asked once as a
// third-party source. The index is dated and the date is shown wherever
// it is used (plan, version, the summary's note), so an old one reads as
// old; azhaq fetches no record it was not given. This package itself does
// no I/O but reading the bytes it is given and, in Confirm, the one read
// its caller counted and scoped.
package advisory

import (
	"encoding/json"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Labels of a Part-1 match.
const (
	LabelAffected    = "affected"
	LabelNotAffected = "not affected"
	LabelConditional = "conditional"
)

// Confidence labels of a Part-2 read. Claimed is a range match only:
// nothing was read that settles it.
const (
	Observed = "observed"
	Inferred = "inferred"
	Claimed  = "claimed"
)

// Reference is one link of an advisory record.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Event is one boundary of an OSV range: introduced (inclusive), fixed
// (exclusive) or last_affected (inclusive), each with its version.
type Event struct {
	Introduced      string `json:"introduced,omitempty"`
	IntroducedAfter string `json:"azhaq_introduced_after,omitempty"` // exclusive: NVD's versionStartExcluding
	Fixed           string `json:"fixed,omitempty"`
	LastAffected    string `json:"last_affected,omitempty"`
}

// Range is one OSV affected range, in the advisory's own syntax.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Package names what an affected entry is about.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Affected is one product's part of an advisory.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Advisory is one public advisory record, the OSV fields azhaq reads.
// The two azhaq_ fields are an extension a dataset may carry beside the
// OSV fields (or under database_specific with the same names): the
// precondition a match alone cannot see, and the one documented read
// that can settle it. Both are read-only by construction (see Confirm).
type Advisory struct {
	ID           string            `json:"id"`
	Summary      string            `json:"summary,omitempty"`
	Aliases      []string          `json:"aliases,omitempty"`
	Affected     []Affected        `json:"affected"`
	References   []Reference       `json:"references,omitempty"`
	Precondition string            `json:"azhaq_precondition,omitempty"`
	ConfirmPath  string            `json:"azhaq_confirm_path,omitempty"`
	Specific     map[string]string `json:"database_specific,omitempty"`
}

// URL is the advisory's own page: its first web reference, else the
// public OSV page for its id.
func (a Advisory) URL() string {
	for _, r := range a.References {
		if r.URL != "" && (r.Type == "WEB" || r.Type == "ADVISORY" || r.Type == "") {
			return r.URL
		}
	}
	if a.ID != "" {
		return "https://osv.dev/vulnerability/" + a.ID
	}
	return ""
}

func (a Advisory) precondition() string {
	if a.Precondition != "" {
		return a.Precondition
	}
	return a.Specific["azhaq_precondition"]
}

func (a Advisory) confirmPath() string {
	if a.ConfirmPath != "" {
		return a.ConfirmPath
	}
	return a.Specific["azhaq_confirm_path"]
}

// Load reads advisory records from OSV JSON bytes: one record, a list of
// them, a {"vulns": [...]} wrapper, or JSON lines (one record a line, as
// an OSV bulk file's per-record files read when joined). A record with
// no id or no affected entry, and a confirm path that is not one plain
// read of the service itself, are errors: a dataset azhaq cannot read
// exactly is not guessed at.
func Load(raw []byte) ([]Advisory, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil, fmt.Errorf("the advisory source is empty")
	}
	var out []Advisory
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	case '{':
		var wrap struct {
			Vulns []Advisory `json:"vulns"`
		}
		if err := json.Unmarshal(raw, &wrap); err == nil && len(wrap.Vulns) > 0 {
			out = wrap.Vulns
			break
		}
		var one Advisory
		if err := json.Unmarshal(raw, &one); err == nil {
			out = []Advisory{one}
			break
		}
		// JSON lines: one whole record a line. A pretty-printed record
		// was already taken whole above, so a line that does not read
		// as one record means the source is not OSV JSON azhaq reads.
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rec Advisory
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				return nil, fmt.Errorf("the advisory source is not OSV JSON (a record, a list of records, or JSON lines)")
			}
			out = append(out, rec)
		}
	default:
		return nil, fmt.Errorf("the advisory source is not OSV JSON (a record, a list of records, or JSON lines)")
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the advisory source holds no advisory records")
	}
	for _, a := range out {
		if a.ID == "" {
			return nil, fmt.Errorf("an advisory record has no id")
		}
		if len(a.Affected) == 0 {
			return nil, fmt.Errorf("advisory %s names no affected product", a.ID)
		}
		if p := a.confirmPath(); p != "" {
			if err := ValidConfirmPath(p); err != nil {
				return nil, fmt.Errorf("advisory %s: %v", a.ID, err)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ValidConfirmPath says p is one benign read: a path on the service
// itself, no scheme, host, query trick or parent step. The method is
// always GET; there is no way to name another.
func ValidConfirmPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//"):
		return fmt.Errorf("confirm path %q is not a path on the service (it must start with one /)", p)
	case strings.ContainsAny(p, "\\# "):
		return fmt.Errorf("confirm path %q holds a character a plain read does not send", p)
	case strings.Contains(p, ".."):
		return fmt.Errorf("confirm path %q steps outside the path it names", p)
	}
	return nil
}

// Service is one product and version azhaq already confirmed, with where
// it was seen. Origin is the web origin a confirmation reads, when the
// service is a web one; Banner is what it said first, when it said
// anything.
type Service struct {
	Host    string `json:"host"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port"`
	Proto   string `json:"proto,omitempty"`
	Service string `json:"service,omitempty"`
	Product string `json:"product"`
	Version string `json:"version"`
	Banner  string `json:"banner,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
	Origin  string `json:"origin,omitempty"`
	// Names are the host strings the listener was reached by (a name, its
	// address): one listener, whichever the run asked it by.
	Names []string `json:"names,omitempty"`
	// AlsoSeen are other versions of the product on the listener that the
	// one chosen does not refine: said, not dropped.
	AlsoSeen []string `json:"also_seen,omitempty"`
	// ObservedAt is when the answer that named it was received, and From the
	// URL it came from when it was a web answer (the proof of an identification).
	ObservedAt time.Time `json:"-"`
	From       string    `json:"-"`
}

// Target names the service for a summary line: host:port.
func (s Service) Target() string {
	host := s.Host
	if host == "" {
		host = s.IP
	}
	if s.Port > 0 {
		return fmt.Sprintf("%s:%d", host, s.Port)
	}
	return host
}

// Address is the IP address of the listener, when the run holds one: the
// scan's own, the one a web answer came from, or the host itself when it is
// an address. A name and its address are one listener.
func (s Service) Address() string {
	if a := normIP(s.IP); a != "" {
		return a
	}
	return normIP(s.Host)
}

// Listener is the key of the listener a service runs on: its address (else
// its host name) and port, and the protocol when it is not TCP.
func (s Service) Listener() string {
	return listenerKey(s.Address(), s.Host, s.Port, s.Proto)
}

func listenerKey(addr, host string, port int, proto string) string {
	h := addr
	if h == "" {
		h = strings.ToLower(host)
	}
	if port > 0 {
		h = fmt.Sprintf("%s:%d", h, port)
	}
	if proto == "udp" {
		h += "/udp"
	}
	return h
}

func normIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// Lead is one labelled match of one service against one advisory. It is
// a lead, never a finding: Label says where the version seen sits in the
// advisory's range, and Confidence, when a confirmation ran, how far a
// benign read settled it.
type Lead struct {
	AdvisoryID    string   `json:"advisory_id"`
	URL           string   `json:"url"`
	Summary       string   `json:"summary,omitempty"`
	Target        string   `json:"target"`
	Host          string   `json:"host"`
	Port          int      `json:"port,omitempty"`
	Address       string   `json:"address,omitempty"`   // the listener's IP address, when the run holds it
	Names         []string `json:"names,omitempty"`     // every host string the listener was reached by
	Proto         string   `json:"proto,omitempty"`     // udp, when it is not TCP
	AlsoSeen      []string `json:"also_seen,omitempty"` // other versions of the product seen on the listener
	Service       string   `json:"service,omitempty"`
	Product       string   `json:"product"`
	VersionSeen   string   `json:"version_seen"`
	AffectedRange string   `json:"affected_range"`
	Label         string   `json:"label"` // affected, not affected or conditional
	Precondition  string   `json:"precondition,omitempty"`
	KEV           bool     `json:"kev,omitempty"`    // CISA lists the advisory as exploited in the wild
	CVSS          float64  `json:"cvss,omitempty"`   // the base score the record states
	Source        string   `json:"source,omitempty"` // the built-in index (with its date), when the record came from it
	// A lead is one service: the fields above are those of its top advisory
	// (the exploited and best scored of those that apply), and these hold
	// the whole list, so nothing is lost by listing one line a service.
	Counts     map[string]int `json:"counts,omitempty"`          // advisories by label
	Advisories []Ref          `json:"advisories,omitempty"`      // all of them, the top first
	KEVCount   int            `json:"kev_count,omitempty"`       // of those that apply, how many CISA lists as exploited
	MaxCVSS    float64        `json:"max_cvss,omitempty"`        // the highest score among those that apply
	IndexLabel string         `json:"index_source,omitempty"`    // the built-in index, for the advisories that came from it
	Confidence string         `json:"confidence,omitempty"`      // observed, inferred or claimed, when confirmation ran
	Read       string         `json:"read,omitempty"`            // what the confirmation read, or why it read nothing
	Origin     string         `json:"origin,omitempty"`          // the web origin of the service, when it is a web one
	ConfirmReq string         `json:"confirm_request,omitempty"` // the exact request a confirmation sent or would send ("GET /version")
}

// Line is the lead as one line of text output: the label, the product
// and version seen, the advisory and its source, and, when a
// confirmation ran, its confidence and what was read.
func (l Lead) Line() string {
	var s string
	if len(l.Advisories) > 1 {
		s = fmt.Sprintf("advisory: %s %s on %s: %s; top %s is %s (range %s) — %s", l.Product, l.VersionSeen, l.where(), l.CountsText(), l.AdvisoryID, l.Label, l.AffectedRange, l.URL)
	} else {
		s = fmt.Sprintf("advisory: %s %s on %s is %s (range %s) — %s %s", l.Product, l.VersionSeen, l.where(), l.Label, l.AffectedRange, l.AdvisoryID, l.URL)
	}
	if len(l.AlsoSeen) > 0 {
		s += "; also seen as " + strings.Join(l.AlsoSeen, ", ")
	}
	if l.KEV {
		s += "; known exploited (CISA KEV)"
	}
	if l.CVSS > 0 {
		s += fmt.Sprintf("; CVSS %.1f", l.CVSS)
	}
	switch {
	case l.Precondition != "":
		s += "; precondition: " + l.Precondition
	case l.Confidence == "" && len(l.Advisories) > 1 && l.Label != LabelNotAffected:
		s += "; range match only, no precondition checked"
	}
	if l.Confidence != "" {
		s += "; confidence " + l.Confidence
	}
	if l.Read != "" {
		s += "; read: " + l.Read
	}
	return s
}

// where is the listener as a line names it: host:port, and the other
// host strings it was reached by ("app.test:80 (also 10.0.0.5)").
func (l Lead) where() string {
	var also []string
	for _, n := range l.Names {
		if !strings.EqualFold(n, l.Host) {
			also = append(also, n)
		}
	}
	if len(also) == 0 {
		return l.Target
	}
	return l.Target + " (also " + strings.Join(also, ", ") + ")"
}

// Listener is the key of the listener a lead is about: its address (else its
// host name) and port.
func (l Lead) Listener() string {
	return listenerKey(l.Address, l.Host, l.Port, l.Proto)
}

// ProductKey folds a product name for comparison: case, spaces, dashes
// and the usual spellings of the same product (Apache httpd, OpenSSH).
func ProductKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(s)
	switch s {
	case "apache", "apachehttpserver", "httpd":
		return "apachehttpd"
	case "ssh":
		return "openssh"
	}
	return s
}

// sameProduct says the advisory's package is the service's product. A
// package name that is a path (an ecosystem's group/name) matches on
// its last part.
func sameProduct(pkg, product string) bool {
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	return ProductKey(pkg) == ProductKey(product)
}

// state is where a version sits in one affected entry.
type state int

const (
	stateOut state = iota
	stateIn
	stateUncertain
)

// Match is every lead of the services against the advisories: one per
// service and advisory that names its product, labelled by where the
// version seen sits in the advisory's range. It sends nothing and reads
// nothing: a pure lookup over what azhaq already holds.
func Match(services []Service, advisories []Advisory) []Lead {
	var out []Lead
	for _, svc := range services {
		if svc.Product == "" || svc.Version == "" {
			continue
		}
		for _, adv := range advisories {
			for _, aff := range adv.Affected {
				if !sameProduct(aff.Package.Name, svc.Product) {
					continue
				}
				out = append(out, leadFor(svc, adv, aff))
			}
		}
	}
	sortLeads(out)
	return out
}

// leadFor labels one service against one affected entry of an advisory:
// where the version seen sits in the entry's range.
func leadFor(svc Service, adv Advisory, aff Affected) Lead {
	st, ranges, why := evalAffected(aff, svc.Version)
	lead := Lead{
		AdvisoryID: adv.ID, URL: adv.URL(), Summary: adv.Summary,
		Target: svc.Target(), Host: firstNonEmpty(svc.Host, svc.IP), Port: svc.Port,
		Address: svc.Address(), Names: svc.Names, Proto: svc.Proto, AlsoSeen: svc.AlsoSeen,
		Service: svc.Service, Product: svc.Product, VersionSeen: svc.Version,
		AffectedRange: ranges, Origin: svc.Origin,
	}
	if p := adv.confirmPath(); p != "" {
		lead.ConfirmReq = "GET " + p
	} else if svc.Origin != "" {
		lead.ConfirmReq = "GET /"
	}
	switch {
	case st == stateUncertain:
		lead.Label = LabelConditional
		lead.Precondition = "the version seen could not be compared with the advisory's range: " + why
	case st == stateOut:
		lead.Label = LabelNotAffected
	case adv.precondition() != "":
		lead.Label = LabelConditional
		lead.Precondition = adv.precondition()
	default:
		lead.Label = LabelAffected
	}
	return lead
}

func labelRank(l string) int {
	switch l {
	case LabelAffected:
		return 0
	case LabelConditional:
		return 1
	}
	return 2
}

// sortLeads orders leads by target, then affected, conditional and not
// affected, the exploited ones and the higher scores first, then by
// advisory id.
func sortLeads(out []Lead) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if ri, rj := labelRank(out[i].Label), labelRank(out[j].Label); ri != rj {
			return ri < rj
		}
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		if out[i].AdvisoryID != out[j].AdvisoryID {
			return out[i].AdvisoryID < out[j].AdvisoryID
		}
		if out[i].VersionSeen != out[j].VersionSeen {
			return out[i].VersionSeen < out[j].VersionSeen
		}
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		return out[i].AffectedRange < out[j].AffectedRange
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// evalAffected is where version sits in one affected entry: its listed
// versions first, then its ranges. why says what was uncertain.
func evalAffected(aff Affected, version string) (state, string, string) {
	for _, v := range aff.Versions {
		if sameVersion(v, version) {
			return stateIn, "version " + v + " listed as affected", ""
		}
	}
	listed := versionsText(aff.Versions)
	if len(aff.Ranges) == 0 {
		if len(aff.Versions) > 0 {
			return stateOut, listed, ""
		}
		return stateUncertain, "no range given", "the advisory gives neither a range nor a list of versions for this product"
	}
	var texts []string
	// What the record states, ranges first and then its listed versions.
	text := func() string {
		parts := append([]string(nil), texts...)
		if listed != "" {
			parts = append(parts, listed)
		}
		return strings.Join(parts, "; ")
	}
	uncertain := ""
	for _, r := range aff.Ranges {
		texts = append(texts, rangeText(r))
		if r.Type != "" && r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
			uncertain = "range type " + r.Type + " is not a version range azhaq compares"
			continue
		}
		st, why := evalRange(r, version)
		switch st {
		case stateIn:
			return stateIn, text(), ""
		case stateUncertain:
			uncertain = why
		}
	}
	if uncertain != "" {
		return stateUncertain, text(), uncertain
	}
	return stateOut, text(), ""
}

// sameVersion says two versions are the same release: equal by Compare
// (8.2p1 and 8.2-p1, 9.0.0.M1 and 9.0.0-m1), else equal as text.
func sameVersion(a, b string) bool {
	if c, ok := Compare(a, b); ok {
		return c == 0
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// versionsText names the versions an advisory lists as affected, one by
// one: "=2.4.49, =2.4.50", cut after eight.
func versionsText(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	shown := vs
	if len(vs) > 8 {
		shown = vs[:8]
	}
	parts := make([]string, len(shown))
	for i, v := range shown {
		parts[i] = "=" + v
	}
	s := strings.Join(parts, ", ")
	if len(vs) > 8 {
		s += fmt.Sprintf(" and %d more", len(vs)-8)
	}
	return s
}

// evalRange walks one range's events in order: the version is in from
// an introduced boundary until a fixed or last_affected one passes it.
func evalRange(r Range, version string) (state, string) {
	if len(r.Events) == 0 {
		return stateUncertain, "a range with no events"
	}
	in := false
	decided := false
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "":
			if ev.Introduced == "0" {
				in, decided = true, true
				continue
			}
			c, ok := Compare(version, ev.Introduced)
			if !ok {
				return stateUncertain, uncertainWhy(version, ev.Introduced)
			}
			if c >= 0 {
				in, decided = true, true
			} else if !decided {
				in = false
			}
		case ev.IntroducedAfter != "":
			c, ok := Compare(version, ev.IntroducedAfter)
			if !ok {
				return stateUncertain, uncertainWhy(version, ev.IntroducedAfter)
			}
			if c > 0 {
				in, decided = true, true
			} else if !decided {
				in = false
			}
		case ev.Fixed != "":
			c, ok := Compare(version, ev.Fixed)
			if !ok {
				return stateUncertain, uncertainWhy(version, ev.Fixed)
			}
			if c >= 0 {
				in = false
			}
			decided = true
		case ev.LastAffected != "":
			c, ok := Compare(version, ev.LastAffected)
			if !ok {
				return stateUncertain, uncertainWhy(version, ev.LastAffected)
			}
			if c > 0 {
				in = false // past the last affected version; a version before the range stays out
			}
			decided = true
		}
	}
	if in {
		return stateIn, ""
	}
	return stateOut, ""
}

func uncertainWhy(seen, bound string) string {
	return fmt.Sprintf("%q against the range boundary %q is not a comparison azhaq can make exactly (a version with no number, or a form outside semver and epoch-version-release)", seen, bound)
}

// rangeText is a range as a reader knows it: ">=1.0.0 <1.2.3",
// "<=2.0.0", "affected versions listed" for a range with no events.
func rangeText(r Range) string {
	var parts []string
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "" && ev.Introduced != "0":
			parts = append(parts, ">="+ev.Introduced)
		case ev.IntroducedAfter != "":
			parts = append(parts, ">"+ev.IntroducedAfter)
		case ev.Fixed != "":
			parts = append(parts, "<"+ev.Fixed)
		case ev.LastAffected != "":
			parts = append(parts, "<="+ev.LastAffected)
		}
	}
	if len(parts) == 0 {
		return "every version"
	}
	return strings.Join(parts, " ")
}

var versionInText = lazyre.New(`(?i)([A-Za-z][A-Za-z0-9 ._-]{0,40}?)[/ ]v?(\d[\w.:+~-]*)`)

// ProductVersion reads a product and version out of a line that names
// them, as a Server header or a version page does ("nginx/1.18.0",
// "OpenSSH 9.6p1"): the first name/number or name number pair.
func ProductVersion(line string) (product, version string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if name, ver, ok := strings.Cut(line, "/"); ok {
		if fields := strings.Fields(name); len(fields) > 0 {
			name = fields[len(fields)-1]
		}
		ver = strings.Fields(ver + " ")[0]
		if name != "" && strings.ContainsAny(ver, "0123456789") {
			return name, strings.Trim(ver, "();,")
		}
	}
	if m := versionInText.FindStringSubmatch(line); m != nil {
		return strings.TrimSpace(m[1]), m[2]
	}
	return "", ""
}
