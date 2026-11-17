package hunt

import (
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/proof"
)

// A listener row is what the run named on one host:port: the product and
// version a service stated, the top advisory its version matches and the label
// it carries, the answer that stated it, and the command that shows it again.
// The command fills them from the same records `azhaq report -findings` lists,
// one for each listener and product; Build ranks them beside the routes and hosts.

// Ident is the part of a row that says what the run named on a listener. With
// -json its fields are the row's own.
type Ident struct {
	Kind        string `json:"kind"`           // identification, or finding for a listener a read proved
	What        string `json:"what,omitempty"` // the record's kind: software-version, advisory-precondition…
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	Product     string `json:"product,omitempty"`
	Version     string `json:"version"`          // "" when no version was seen
	Source      string `json:"source,omitempty"` // what a name's root page said to name the product: page title, generator, header X-Powered-By, header Server, technology
	AdvisoryID  string `json:"advisory_id,omitempty"`
	AdvisoryURL string `json:"advisory_url,omitempty"`
	Advisories  int    `json:"advisories,omitempty"` // how many advisories match the version, the top one included
	// Next are the advisories that follow the top one in the same order (the
	// first few), and Others how many more match, by label: the text row names
	// these and counts the rest, and report -findings lists every one.
	Next     []NextAdvisory `json:"next_advisories,omitempty"`
	Others   map[string]int `json:"other_advisories,omitempty"`
	Label    string         `json:"label"` // proved, version-read, version-only or conditional: as report -findings says it
	Severity string         `json:"severity"`
	KEV      bool           `json:"kev,omitempty"`
	CVSS     float64        `json:"cvss,omitempty"`
	Evidence string         `json:"evidence"`
	Command  string         `json:"command,omitempty"` // the command that produced the record
	// Also lists the other host names whose own answer named this product and
	// version (its address, a name that resolves to it): one row for the service,
	// whatever it was reached as. A name that read another product is not here.
	Also []string `json:"also_named,omitempty"`
}

// NextAdvisory is an advisory of a listener's product and version that follows
// the row's top one.
type NextAdvisory struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	KEV   bool    `json:"kev,omitempty"`
	CVSS  float64 `json:"cvss,omitempty"`
}

// Tags are what the row says of it beside its id.
func (n NextAdvisory) Tags() string {
	t := []string{n.Label}
	if n.KEV {
		t = append(t, "KEV")
	}
	if n.CVSS > 0 {
		t = append(t, fmt.Sprintf("CVSS %.1f", n.CVSS))
	}
	return strings.Join(t, ", ")
}

// Listener is one record for Build: the Ident fields and its proof.
type Listener struct {
	Ident
	Proof *proof.Proof
}

// ListenerRows are the rows Build makes of listeners, in the order given and
// unranked (Rank 0: a rank is only known once every row of the workspace is
// ordered). A run that is still going lists them as it names each listener.
func ListenerRows(ls []Listener, db string) []Row {
	out := make([]Row, len(ls))
	for i, l := range ls {
		out[i] = l.row(db)
	}
	return out
}

// label scores, before the exploited and the score the advisory states.
var listenerScore = map[string]int{"proved": 90, "version-read": 70, "version-only": 60, "conditional": 50}

func (l Listener) row(db string) Row {
	id := l.Ident
	key := id.Host
	if id.Port > 0 {
		key = fmt.Sprintf("%s:%d", id.Host, id.Port)
	}
	named := strings.TrimSpace(id.Product + " " + id.Version)
	if id.Product == "" {
		named = "a service"
	}
	if id.Version == "" {
		named += " (no version seen)"
	}
	if id.Source != "" {
		named += ", named by " + id.Source
	}
	if len(id.Also) > 0 {
		named += "; also answered as " + join(id.Also, 4)
	}
	rs := []Reason{{"identified", named}}
	if id.AdvisoryID != "" {
		d := id.AdvisoryID + " " + id.Label
		if id.KEV {
			d += ", known exploited (CISA KEV)"
		}
		if id.CVSS > 0 {
			d += fmt.Sprintf(", CVSS %.1f", id.CVSS)
		}
		if id.Advisories > 1 {
			d += fmt.Sprintf("; %d advisories match this version", id.Advisories)
			if len(id.Next) > 0 {
				var next []string
				for _, n := range id.Next {
					next = append(next, n.ID+" ("+n.Tags()+")")
				}
				d += ", then " + strings.Join(next, ", ")
				if more := id.Advisories - 1 - len(id.Next); more > 0 {
					d += fmt.Sprintf(" and %d more: %s", more, othersText(id.Others))
				}
			}
			d += fmt.Sprintf("; azhaq report -findings -db %s lists them", quote(db))
		}
		rs = append(rs, Reason{"advisory", d})
	} else if id.Kind == proof.TierFinding {
		rs = append(rs, Reason{"read", id.Evidence})
	}
	next := id.Command
	if l.Proof != nil {
		if l.Proof.Excerpt != "" {
			rs = append(rs, Reason{"proof", clip(l.Proof.Excerpt, 120)})
		}
		if l.Proof.Reproduce != "" {
			next = l.Proof.Reproduce
		}
	}
	if next == "" {
		next = "azhaq report -findings -db " + quote(db)
	}
	score := listenerScore[id.Label]
	switch {
	case id.Version == "":
		score = 10
	case id.AdvisoryID == "" && id.Kind != proof.TierFinding:
		score = 30
	}
	if id.Kind == proof.TierFinding {
		score = 100
	}
	if id.KEV {
		score += 10
	}
	score += int(id.CVSS)
	row := Row{Score: score, Key: key, Type: "Service", Reasons: rs, Next: next, Tier: proof.TierIdentification, Proof: l.Proof, Ident: &id, scope: "target", signals: len(rs)}
	if id.Kind == proof.TierFinding {
		row.Tier = proof.TierFinding
	}
	return row
}

// tierRank orders the tiers: a proven finding, an identification with a
// version, an identification with no version seen, then the leads.
func (r Row) tierRank() int {
	switch {
	case r.Tier == proof.TierFinding:
		return 0
	case r.Tier == proof.TierIdentification && r.Ident != nil && r.Ident.Version != "":
		return 1
	case r.Tier == proof.TierIdentification:
		return 2
	}
	return 3
}

// Measured is a finding of the findings output that no route or listener
// holds: what a DNS answer showed of a name (a CNAME to a name that answered
// NXDOMAIN), or the stack trace an answer carried. It is a row of its own, a
// finding ranked by its severity beside the others, never merged with a lead
// about the same name or route.
type Measured struct {
	Kind     string // dangling-dns, error-disclosure, sql-error, debug-page, directory-listing, graphql-schema, graphql-ide, cross-role-access
	Type     string // the row's type: Hostname when empty, URL for a route
	Host     string // the row's key: the name, or the URL
	Severity string
	Evidence string
	Command  string
	Proof    *proof.Proof
	// Score and Next, when set, replace the rank the severity gives and the
	// command the proof reproduces: a roles verdict ranks as it always has and
	// is shown again by roles show.
	Score int
	Next  string
}

// measuredScore is a measured finding's score by severity: below what a proven
// access hole or a known secret weighs, above every identification and lead.
var measuredScore = map[string]int{"info": 15, "low": 30, "medium": 50, "high": 70, "critical": 90}

func (m Measured) row(db string) Row {
	next := m.Command
	if m.Proof != nil && m.Proof.Reproduce != "" {
		next = m.Proof.Reproduce
	}
	if m.Next != "" {
		next = m.Next
	}
	if next == "" {
		next = "azhaq report -findings -db " + quote(db)
	}
	rs := []Reason{{m.Kind, m.Evidence}}
	typ := m.Type
	if typ == "" {
		typ = "Hostname"
	}
	score := measuredScore[m.Severity]
	if m.Score > 0 {
		score = m.Score
	} else if s := ProvedScore(m.Kind); s > 0 {
		score = s
	}
	return Row{Score: score, Key: m.Host, Type: typ, Reasons: rs, Next: next,
		Tier: proof.TierFinding, Proof: m.Proof, scope: "target", signals: 1}
}

// othersText tells the other advisories of a row by label, as report -findings
// names them ("30 version-only, 8 conditional").
func othersText(m map[string]int) string {
	var parts []string
	for _, lb := range []string{"proved", "version-read", "version-only", "conditional"} {
		if n := m[lb]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, lb))
		}
	}
	return strings.Join(parts, ", ")
}

// Lead is a product only the hash of an icon named on a listener: a lead with
// the read that would settle it, never an identification. It ranks with the
// leads, below every identification.
type Lead struct {
	Host     string
	Port     int
	Evidence string // "favicon matches X or Y", with what the run asked
	Check    string
	Command  string
}

// leadScore is below any identification and any route's signal: an icon is
// the weakest name there is.
const leadScore = 5

func (l Lead) row() Row {
	key := l.Host
	if l.Port > 0 {
		key = fmt.Sprintf("%s:%d", l.Host, l.Port)
	}
	return Row{Score: leadScore, Key: key, Type: "Service", Reasons: []Reason{{"favicon", l.Evidence}}, Next: l.Command,
		Tier: proof.TierLead, Check: l.Check, scope: "target", signals: 1}
}
