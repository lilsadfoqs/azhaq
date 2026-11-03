package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
// one unit a case (claimCaseIDs); regress and checklist run only when -only (or -checklist) names them.
var onceSections = []string{"dropin", "scope", "secrets", "tenants", "scale", "claims", "regress", "network", "lab", "openapi", "docs", "deploy", "checklist"}

var profileOrder = []string{profDefault, profPolite}

// unitName is the name of a comparison section in a profile.
func unitName(profile, section string) string { return profile + ":" + section }

// cmpUnitNames are the units of one comparison section in a profile: one,
// but for domains one per domain ("default:domains/hackerone.com"), which
// are the longest and the most variable. The polite profile looks up only
// politeDomains; all lists them whatever the flag says.
func cmpUnitNames(profile, section string, all bool) []string {
	if section != "domains" {
		return []string{unitName(profile, section)}
	}
	var out []string
	for _, d := range domainList() {
		if all || profile != profPolite || slices.Contains(politeDomains, d) {
			out = append(out, unitName(profile, "domains/"+d))
		}
	}
	return out
}

// canonicalUnits is every unit in the order one full run writes its
// checks: the default profile's comparisons, the polite ones, then the
// sections that run once.
func canonicalUnits() []string {
	var out []string
	for _, p := range profileOrder {
		for _, s := range cmpSections {
			out = append(out, cmpUnitNames(p, s, true)...)
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

// unitSection is the section a unit belongs to ("default:apps" → "apps",
// "polite:domains/vulnweb.com" → "domains").
func unitSection(name string) string {
	_, s, _ := strings.Cut(name, ":")
	if strings.HasPrefix(name, "claims:") {
		return "claims"
	}
	s, _, _ = strings.Cut(s, "/")
	return s
}

// plannedUnits are the units a run with these settings would take: the
// profiles, and a section's on(profile, section) answer.
func plannedUnits(profiles []string, on func(unit, section string) bool) []string {
	var out []string
	for _, p := range profiles {
		for _, s := range cmpSections {
			for _, u := range cmpUnitNames(p, s, false) {
				if on(u, s) {
					out = append(out, u)
				}
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

// unitStop is what fatal panics with inside a unit: the unit ends, the
// record keeps the units already done.
type unitStop struct{ msg string }

// inUnit is the unit now running, "" outside units (flags, setup).
var inUnit string

// trackUnit runs fn and records what it added to the record. rows, when
// set, counts the claims table's rows. A unit that dies (a bench error
// through fatal, or a panic) becomes a failed check of its own: the process
// goes on with the next unit, and the record holds every unit that ran.
func trackUnit(name string, rows func() int, fn func()) {
	c0, r0, w0 := len(rec.Checks), len(rec.Runs), 0
	if rows != nil {
		w0 = rows()
	}
	func() {
		inUnit = name
		defer func() {
			inUnit = ""
			if r := recover(); r != nil {
				msg := fmt.Sprint(r)
				if st, ok := r.(unitStop); ok {
					msg = st.msg
				} else {
					msg = "panic: " + msg
				}
				noCache, beforeEach = false, nil // a median loop may have stopped halfway
				logf("unit %s stopped: %s", name, msg)
				prefix := ""
				if prof != "" {
					prefix = "[" + prof + "] "
				}
				rec.Checks = append(rec.Checks, check{Name: prefix + "unit " + name + ": ran to its end", Pass: false, Detail: msg})
			}
		}()
		fn()
	}()
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

// setupFailed ends a run whose setup (the build of azhaq, the install of a
// reference tool) failed before any unit began. The tool's own output goes to
// the log, and the record holds one failed check for each unit the run
// planned, with that output in its detail, so a job that built nothing is
// diagnosed from its record and the merge does not report "no result".
func setupFailed(dir, what string, err error, output []byte, planned []string) {
	text := strings.TrimSpace(err.Error())
	if o := strings.TrimSpace(string(output)); o != "" {
		text += "\n" + o
	}
	text = strings.ReplaceAll(text, work, "bench/.work")
	logf("%s failed for %s:\n%s", what, unitsText(planned), text)
	noteSetupFailure(what, text, planned)
	if e := os.MkdirAll(dir, 0o755); e == nil {
		name := filepath.Join(dir, recordName(time.Now().UTC().Format(time.RFC3339), rec.Commit))
		raw, _ := json.MarshalIndent(rec, "", "  ")
		if e := os.WriteFile(name, append(raw, '\n'), 0o644); e == nil {
			fmt.Printf("record %s\n", name)
		}
	}
	os.Exit(2)
}

// noteSetupFailure puts the failure in the record: one failed check for each
// planned unit, or one of its own when the run planned none.
func noteSetupFailure(what, text string, planned []string) {
	detail := what + " failed: " + clipText(text, 4000)
	if len(planned) == 0 {
		rec.Checks = append(rec.Checks, check{Name: "setup: " + what, Pass: false, Detail: detail})
	}
	for _, u := range planned {
		name := "unit " + u + ": ran to its end"
		if p, _, ok := strings.Cut(u, ":"); ok && slices.Contains(profileOrder, p) {
			name = "[" + p + "] " + name
		}
		rec.Checks = append(rec.Checks, check{Name: name, Pass: false, Detail: detail})
		rec.Units = append(rec.Units, unitSpan{Name: u, Checks: 1})
	}
}

func unitsText(planned []string) string {
	if len(planned) == 0 {
		return "this run"
	}
	return "units " + strings.Join(planned, ", ")
}

// clipText keeps the head and the tail of s, which is where a compiler puts
// the first error and the summary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n/2] + "\n[...]\n" + s[len(s)-n/2:]
}
