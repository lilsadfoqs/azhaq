package main

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// A unit is the smallest piece of the bench a job can run alone: one
// comparison section in one profile ("default:apps", "polite:dirs"), one
// claims case ("claims:5") or one of the sections that run once
// ("once:dropin"). CI packs the units into jobs by their measured times
// (.github/ci/bench-plan.py) and joins the records (-merge). No section
// reads another's results: the sections share only caches (liveCache) and
// the reference tools' replayed runs, which are keyed by command, so every
// unit stands alone.

// cmpSections are the comparison sections, in the order a run takes them.
var cmpSections = []string{"apps", "dirs", "fuzz", "shots", "params", "domains", "urls", "brute", "dns", "ports", "services", "probe", "notify"}

// onceSections run once, after the comparisons, in this order. claims is
// one unit a case (claimCaseIDs); regress runs only when -only names it.
var onceSections = []string{"dropin", "scope", "secrets", "tenants", "scale", "claims", "regress", "network", "lab", "openapi", "docs"}

var profileOrder = []string{profDefault, profPolite}

// unitName is the name of a comparison section in a profile.
func unitName(profile, section string) string { return profile + ":" + section }

// canonicalUnits is every unit in the order one full run writes its
// checks: the default profile's comparisons, the polite ones, then the
// sections that run once.
func canonicalUnits() []string {
	var out []string
	for _, p := range profileOrder {
		for _, s := range cmpSections {
			out = append(out, unitName(p, s))
		}
	}
	for _, s := range onceSections {
		if s == "claims" {
			for _, id := range claimCaseIDs() {
				out = append(out, "claims:"+id)
			}
			continue
		}
		out = append(out, "once:"+s)
	}
	return out
}

// unitRank orders names as canonicalUnits does; a name it does not know
// sorts after all of them.
func unitRank(name string) int {
	if i := slices.Index(canonicalUnits(), name); i >= 0 {
		return i
	}
	return len(canonicalUnits())
}

// parseUnits checks a -units or -expect list: comma-separated names from canonicalUnits.
func parseUnits(list string) ([]string, error) {
	var out []string
	known := canonicalUnits()
	for _, u := range strings.Split(list, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		if !slices.Contains(known, u) {
			return nil, fmt.Errorf("no unit %q (units: %s)", u, strings.Join(known, ", "))
		}
		out = append(out, u)
	}
	return out, nil
}

// unitSection is the section a unit belongs to ("default:apps" → "apps").
func unitSection(name string) string {
	_, s, _ := strings.Cut(name, ":")
	if strings.HasPrefix(name, "claims:") {
		return "claims"
	}
	return s
}

// plannedUnits are the units a run with these settings would take: the
// profiles, and a section's on(profile, section) answer.
func plannedUnits(profiles []string, on func(unit, section string) bool) []string {
	var out []string
	for _, p := range profiles {
		for _, s := range cmpSections {
			if u := unitName(p, s); on(u, s) {
				out = append(out, u)
			}
		}
	}
	for _, s := range onceSections {
		if s == "claims" {
			for _, id := range claimCaseIDs() {
				if u := "claims:" + id; on(u, s) {
					out = append(out, u)
				}
			}
			continue
		}
		if u := "once:" + s; on(u, s) {
			out = append(out, u)
		}
	}
	return out
}

// unitSpan says how much of a record one unit wrote: the merge uses it to
// put the checks and runs of units that ran in different jobs in the order
// of one run. Rows is a claims case's rows in the claims table.
type unitSpan struct {
	Name   string `json:"name"`
	Checks int    `json:"checks"`
	Runs   int    `json:"runs"`
	Rows   int    `json:"rows,omitempty"`
}

// trackUnit runs fn and records what it added to the record. rows, when
// set, counts the claims table's rows.
func trackUnit(name string, rows func() int, fn func()) {
	c0, r0, w0 := len(rec.Checks), len(rec.Runs), 0
	if rows != nil {
		w0 = rows()
	}
	fn()
	span := unitSpan{Name: name, Checks: len(rec.Checks) - c0, Runs: len(rec.Runs) - r0}
	if rows != nil {
		span.Rows = rows() - w0
	}
	rec.Units = append(rec.Units, span)
}

// runUnit tracks a unit and logs how long it took (bench-times.py reads
// these lines to plan the next run).
func runUnit(name string, fn func()) {
	t0 := time.Now()
	trackUnit(name, nil, fn)
	profile, section, _ := strings.Cut(name, ":")
	logf("%s: %s took %.0fs", profile, section, time.Since(t0).Seconds())
}
