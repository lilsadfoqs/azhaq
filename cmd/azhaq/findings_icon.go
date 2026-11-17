package main

import (
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/proof"
)

// iconKind is the kind of a lead that a product's icon hash named: nothing
// else did, and no read of the product has settled it.
const iconKind = "favicon-match"

// iconLeadRecord is the lead for the products one icon hash matched on a name
// and port: no version, no advisory, with what was asked and the check that
// would settle it.
func iconLeadRecord(l advisory.IconLead, command string) findingRecord {
	ev := l.Says()
	if l.Hash != "" {
		ev += " (hash " + l.Hash
		if l.IconURL != "" {
			ev += " of " + l.IconURL
		}
		ev += ")"
	}
	ev += "; asked: " + strings.Join(l.Asked, "; ")
	return findingRecord{
		Tier: proof.TierLead, Kind: iconKind, Label: "lead", Severity: "info",
		Host: l.Host, Port: l.Port, URL: l.Origin, Product: strings.Join(l.Products, " or "),
		Evidence: ev, Command: command, Collector: "azhaq-http",
		Check: "read the name from the service itself: a header, the page text or a path only " + strings.Join(l.Products, " or ") +
			" answers; a favicon is shared by every site built from the same template, so its hash alone names no product",
	}
}

// iconLeads are the leads of a findings set that hunt lists as rows.
func iconLeads(set findingSet) []hunt.Lead {
	var out []hunt.Lead
	for _, r := range set.Leads {
		if r.Kind != iconKind {
			continue
		}
		out = append(out, hunt.Lead{Host: r.Host, Port: r.Port, Evidence: r.Evidence, Check: r.Check,
			Command: fmt.Sprintf("curl -sS -i --max-time 10 %s", shellQuote(strings.TrimRight(r.URL, "/")+"/"))})
	}
	return out
}
