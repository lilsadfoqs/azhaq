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
	Kind        string  `json:"kind"`           // identification, or finding for a listener a read proved
	What        string  `json:"what,omitempty"` // the record's kind: software-version, advisory-precondition…
	Host        string  `json:"host"`
	Port        int     `json:"port,omitempty"`
	Product     string  `json:"product,omitempty"`
	Version     string  `json:"version"` // "" when no version was seen
	AdvisoryID  string  `json:"advisory_id,omitempty"`
	AdvisoryURL string  `json:"advisory_url,omitempty"`
	Advisories  int     `json:"advisories,omitempty"` // how many advisories match the version, the top one included
	Label       string  `json:"label"`                // proved, version-only or conditional: as report -findings says it
	Severity    string  `json:"severity"`
	KEV         bool    `json:"kev,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Evidence    string  `json:"evidence"`
	Command     string  `json:"command,omitempty"` // the command that produced the record
}

// Listener is one record for Build: the Ident fields and its proof.
type Listener struct {
	Ident
	Proof *proof.Proof
}

// label scores, before the exploited and the score the advisory states.
var listenerScore = map[string]int{"proved": 90, "version-only": 60, "conditional": 50}

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
			d += fmt.Sprintf("; %d advisories match this version, azhaq report -findings -db %s lists them", id.Advisories, quote(db))
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
