package main

import "fmt"

// tierRow is one printed row of subs: its name and its tier.
type tierRow struct {
	Host string `json:"host"`
	Tier string `json:"tier"`
}

// tierProblems checks the tiers of a subs -live run against the reference
// tool's answer: every row is DNS-confirmed (a lookup said so), the summary
// counts a raw candidate apart from a confirmed name, the DNS-confirmed
// names are at least the reference's confirmed ones, and no raw candidate
// is counted as confirmed. refLive is what the reference's names resolve
// to at a resolver neither tool used.
func tierProblems(rows []tierRow, counts map[string]int, refLive map[string]bool) []string {
	var out []string
	printed := map[string]bool{}
	for _, r := range rows {
		printed[r.Host] = true
		if r.Tier != "dns" && r.Tier != "http" {
			out = append(out, fmt.Sprintf("%s is printed as tier %q in a -live run", r.Host, r.Tier))
		}
	}
	if counts["raw candidates"] < len(rows)-counts["found as CNAME targets"]-counts["found by guessing"] {
		out = append(out, fmt.Sprintf("%d raw candidates for %d printed rows", counts["raw candidates"], len(rows)))
	}
	if counts["DNS-confirmed"] != len(rows) {
		out = append(out, fmt.Sprintf("DNS-confirmed %d, rows %d", counts["DNS-confirmed"], len(rows)))
	}
	if counts["DNS-confirmed"] > counts["raw candidates"]+counts["found as CNAME targets"]+counts["found by guessing"] {
		out = append(out, fmt.Sprintf("DNS-confirmed %d exceeds raw candidates %d and what lookups added", counts["DNS-confirmed"], counts["raw candidates"]))
	}
	missing := 0
	for n := range refLive {
		if !printed[n] {
			missing++
		}
	}
	if missing > 0 {
		out = append(out, fmt.Sprintf("%d names the reference's lookups confirmed are not DNS-confirmed here", missing))
	}
	return out
}
