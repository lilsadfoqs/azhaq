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

// mergeRecords joins the records of units run apart (CI runs each group of
// units on its own runner) into one record, as one run writes: the checks,
// runs and claims rows of every unit in the order of a single run
// (canonicalUnits). A unit in expect that no record holds becomes a failed
// check at its place. Records without unit spans (older ones) are appended
// in the order given.
func mergeRecords(paths []string, out string, expect []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("-merge: name the records to join")
	}
	all := map[string]any{}
	units := map[string]*unitData{}
	var seen []string // the units in the order they were found
	claimSecs, hasClaims := 0.0, false
	for i, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		if a, b := all["commit"], r["commit"]; a != nil && b != nil && a != b {
			return fmt.Errorf("%s measures commit %v, the others %v", p, b, a)
		}
		parts, err := splitUnits(r, i)
		if err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		for _, u := range parts {
			if _, dup := units[u.name]; dup {
				u = &unitData{name: u.name, checks: []any{map[string]any{"name": "unit " + u.name + ": two records hold it", "pass": false,
					"detail": "the second one (" + filepath.Base(p) + ") was dropped; the plan gave the unit to two jobs"}}}
				units[u.name+"\x00"+p] = u
				seen = append(seen, u.name+"\x00"+p)
				continue
			}
			units[u.name] = u
			seen = append(seen, u.name)
		}
		if c, ok := r["claims"].(map[string]any); ok {
			hasClaims = true
			if f, ok := c["seconds"].(float64); ok {
				claimSecs += f
			}
			delete(c, "rows")
			delete(c, "seconds")
		}
		delete(r, "checks")
		delete(r, "runs")
		delete(r, "units")
		mergeInto(all, r)
	}
	for _, u := range expect {
		if _, ok := units[u]; !ok {
			units[u] = &unitData{name: u, checks: []any{map[string]any{"name": "unit " + u + ": no result", "pass": false,
				"detail": "no record holds it: the job that ran it wrote none, or stopped before it (see that job's log)"}}}
			seen = append(seen, u)
		}
	}
	slices.SortStableFunc(seen, func(a, b string) int {
		return unitRank(strings.SplitN(a, "\x00", 2)[0]) - unitRank(strings.SplitN(b, "\x00", 2)[0])
	})
	var checks, runs, rows, spans []any
	for _, k := range seen {
		u := units[k]
		checks, runs, rows = append(checks, u.checks...), append(runs, u.runs...), append(rows, u.rows...)
		if u.span {
			spans = append(spans, map[string]any{"name": u.name, "checks": len(u.checks), "runs": len(u.runs), "rows": len(u.rows)})
		}
	}
	all["checks"], all["runs"] = checks, runs
	sortDomains(all)
	if p, ok := all["polite"].(map[string]any); ok {
		sortDomains(p)
	}
	if len(spans) > 0 {
		all["units"] = spans
	}
	if hasClaims {
		c, _ := all["claims"].(map[string]any)
		if c == nil {
			c = map[string]any{}
			all["claims"] = c
		}
		c["rows"], c["seconds"] = rows, claimSecs
	}
	raw, _ := json.Marshal(all)
	rec = record{}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	printReport()
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	name := filepath.Join(out, recordName(rec.Date, rec.Commit))
	b, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(name, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("\nrecord %s (joined from %d)\n", name, len(paths))
	return nil
}

// unitData is what one unit wrote to a record. span is false for what no
// span names (an older record, or the tail after the last span).
type unitData struct {
	name               string
	checks, runs, rows []any
	span               bool
}

// splitUnits cuts a record's checks, runs and claims rows into its units by
// the spans it holds. What no span covers goes to a unit of its own that
// sorts after the known ones, in file order.
func splitUnits(r map[string]any, idx int) ([]*unitData, error) {
	checks, _ := r["checks"].([]any)
	runs, _ := r["runs"].([]any)
	var rows []any
	if c, ok := r["claims"].(map[string]any); ok {
		rows, _ = c["rows"].([]any)
	}
	spans, _ := r["units"].([]any)
	var out []*unitData
	ci, ri, wi := 0, 0, 0
	for _, sp := range spans {
		m, _ := sp.(map[string]any)
		name, _ := m["name"].(string)
		n := func(k string) int { f, _ := m[k].(float64); return int(f) }
		nc, nr, nw := n("checks"), n("runs"), n("rows")
		if name == "" || ci+nc > len(checks) || ri+nr > len(runs) || wi+nw > len(rows) {
			return nil, fmt.Errorf("the unit spans do not match the record's checks, runs and claims rows")
		}
		out = append(out, &unitData{name: name, checks: checks[ci : ci+nc], runs: runs[ri : ri+nr], rows: rows[wi : wi+nw], span: true})
		ci, ri, wi = ci+nc, ri+nr, wi+nw
	}
	if ci < len(checks) || ri < len(runs) || wi < len(rows) {
		out = append(out, &unitData{name: fmt.Sprintf("~%03d", idx), checks: checks[ci:], runs: runs[ri:], rows: rows[wi:]})
	}
	return out, nil
}

// mergeInto adds src to dst: lists of checks and runs are joined, tools
// are listed once, the earliest date stays, and each section's row comes
// from the record that measured it.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			continue
		}
		switch k {
		case "checks", "runs", "domains": // domains: one row a unit, ordered after the join
			a, _ := dst[k].([]any)
			b, _ := v.([]any)
			dst[k] = append(a, b...)
			continue
		case "tools":
			a, _ := dst[k].([]any)
			seen := map[string]bool{}
			for _, t := range a {
				seen[fmt.Sprint(t.(map[string]any)["name"])] = true
			}
			for _, t := range v.([]any) {
				if n := fmt.Sprint(t.(map[string]any)["name"]); !seen[n] {
					seen[n] = true
					a = append(a, t)
				}
			}
			dst[k] = a
			continue
		case "date":
			if d, ok := dst[k].(string); ok && d <= v.(string) {
				continue
			}
		}
		if m, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				mergeInto(d, m)
				continue
			}
		}
		if dst[k] == nil || k == "date" {
			dst[k] = v
		}
	}
}

// recordName is the file name of a record taken at date (RFC 3339).
func recordName(date, commit string) string {
	t, err := time.Parse(time.RFC3339, date)
	if err != nil {
		t = time.Now()
	}
	return t.UTC().Format("2006-01-02T150405") + "-" + commit + ".json"
}

// sortDomains puts the domain rows of a joined profile in the order of the
// domain list, as one run writes them.
func sortDomains(set map[string]any) {
	rows, _ := set["domains"].([]any)
	order := domainList()
	idx := func(r any) int {
		m, _ := r.(map[string]any)
		d, _ := m["domain"].(string)
		if i := slices.Index(order, d); i >= 0 {
			return i
		}
		return len(order)
	}
	slices.SortStableFunc(rows, func(a, b any) int { return idx(a) - idx(b) })
}
