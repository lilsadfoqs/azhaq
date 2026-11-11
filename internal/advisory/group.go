package advisory

import (
	"fmt"
	"sort"
	"strings"
)

// Ref is one advisory of a service's lead: what a reader needs to find it
// again and to tell it from the others.
type Ref struct {
	ID           string  `json:"id"`
	URL          string  `json:"url"`
	Label        string  `json:"label"`
	Range        string  `json:"range,omitempty"`
	KEV          bool    `json:"kev,omitempty"`
	CVSS         float64 `json:"cvss,omitempty"`
	Index        bool    `json:"index,omitempty"` // it came from the built-in index
	Precondition string  `json:"precondition,omitempty"`
	Confidence   string  `json:"confidence,omitempty"` // when a confirmation ran
	ConfirmReq   string  `json:"confirm_request,omitempty"`
	Read         string  `json:"read,omitempty"` // what the read said of this advisory, when it differs from the lead's
}

func applies(label string) bool { return label != LabelNotAffected }

// Group makes one lead of each service (host, port, product and version)
// out of the leads of its advisories. The lead's own fields are those of its
// top advisory, and Advisories lists them all: the ones that apply first
// (affected, conditional), CISA KEV before the rest, the higher score
// first, then by id. Counts, KEVCount and MaxCVSS summarise the list.
func Group(leads []Lead) []Lead {
	type key struct{ target, product, version string }
	at := map[key]int{}
	var members [][]Lead
	for _, l := range leads {
		k := key{l.Target, l.Product, l.VersionSeen}
		i, ok := at[k]
		if !ok {
			i = len(members)
			at[k] = i
			members = append(members, nil)
		}
		members[i] = append(members[i], l)
	}
	var out []Lead
	for _, ms := range members {
		sort.SliceStable(ms, func(i, j int) bool {
			a, b := ms[i], ms[j]
			if applies(a.Label) != applies(b.Label) {
				return applies(a.Label)
			}
			if a.KEV != b.KEV {
				return a.KEV
			}
			if a.CVSS != b.CVSS {
				return a.CVSS > b.CVSS
			}
			return a.AdvisoryID < b.AdvisoryID
		})
		g := ms[0]
		g.Counts = map[string]int{}
		g.Advisories = nil
		g.KEVCount, g.MaxCVSS = 0, 0
		for _, m := range ms {
			g.Counts[m.Label]++
			ref := Ref{ID: m.AdvisoryID, URL: m.URL, Label: m.Label, Range: m.AffectedRange, KEV: m.KEV, CVSS: m.CVSS, Precondition: m.Precondition}
			if m.Source != "" {
				ref.Index = true
				g.IndexLabel = m.Source
			}
			g.Advisories = append(g.Advisories, ref)
			if applies(m.Label) {
				if m.KEV {
					g.KEVCount++
				}
				if m.CVSS > g.MaxCVSS {
					g.MaxCVSS = m.CVSS
				}
			}
		}
		out = append(out, g)
	}
	sortLeadsByTarget(out)
	return out
}

func sortLeadsByTarget(out []Lead) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		if out[i].Product != out[j].Product {
			return out[i].Product < out[j].Product
		}
		return out[i].VersionSeen < out[j].VersionSeen
	})
}

// Expand is the advisories of a service's lead as one lead each, as
// Match made them: for the findings, which list every advisory.
func (l Lead) Expand() []Lead {
	if len(l.Advisories) == 0 {
		return []Lead{l}
	}
	out := make([]Lead, 0, len(l.Advisories))
	for i, r := range l.Advisories {
		e := l
		e.Counts, e.Advisories, e.KEVCount, e.MaxCVSS, e.IndexLabel = nil, nil, 0, 0, ""
		e.AdvisoryID, e.URL, e.Label, e.AffectedRange, e.KEV, e.CVSS = r.ID, r.URL, r.Label, r.Range, r.KEV, r.CVSS
		e.Precondition, e.Confidence, e.ConfirmReq, e.Source = r.Precondition, r.Confidence, r.ConfirmReq, ""
		if r.Index {
			e.Source = l.IndexLabel
		}
		if i > 0 {
			// What the lead says was read stands for the advisories that say nothing else.
			e.Read = r.Read
			if e.Read == "" && r.Confidence != "" {
				e.Read = l.Read
			}
		}
		out = append(out, e)
	}
	return out
}

// CountsText is the labels of a lead's advisories as a phrase: "90
// affected, 2 conditional, 3 not affected (12 on KEV; highest CVSS 9.8)".
func (l Lead) CountsText() string {
	var parts []string
	for _, lb := range []string{LabelAffected, LabelConditional, LabelNotAffected} {
		if n := l.Counts[lb]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, lb))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no advisory")
	}
	s := strings.Join(parts, ", ")
	var extra []string
	if l.KEVCount > 0 {
		extra = append(extra, fmt.Sprintf("%d on KEV", l.KEVCount))
	}
	if l.MaxCVSS > 0 {
		extra = append(extra, fmt.Sprintf("highest CVSS %.1f", l.MaxCVSS))
	}
	if len(extra) > 0 {
		s += " (" + strings.Join(extra, "; ") + ")"
	}
	return s
}

// Brief is a lead as the short line of the run's observations:
// "Apache httpd 2.4.49: 90 affected (12 on KEV; highest CVSS 9.8), top
// CVE-2021-41773 (KEV, 9.8)".
func (l Lead) Brief() string {
	s := fmt.Sprintf("%s %s: %s, top %s", l.Product, l.VersionSeen, l.CountsText(), l.AdvisoryID)
	var tags []string
	if l.KEV {
		tags = append(tags, "KEV")
	}
	if l.CVSS > 0 {
		tags = append(tags, fmt.Sprintf("%.1f", l.CVSS))
	}
	if len(tags) > 0 {
		s += " (" + strings.Join(tags, ", ") + ")"
	}
	return s
}

// IDs is the advisory ids of a lead, the first max of them, and how many
// more there are: "CVE-A, CVE-B and 88 more". max <= 0 lists all.
func (l Lead) IDs(max int) string {
	var ids []string
	for _, r := range l.Advisories {
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		ids = []string{l.AdvisoryID}
	}
	return CollapseIDs(ids, max)
}

// CollapseIDs lists the first max ids and says how many more there are.
func CollapseIDs(ids []string, max int) string {
	if max <= 0 || len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(ids[:max], ", "), len(ids)-max)
}
