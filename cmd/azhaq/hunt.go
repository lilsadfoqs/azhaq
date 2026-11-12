package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/takeover"
	"github.com/lilsadfoqs/azhaq/types"
)

// cmdHunt ranks a workspace's surface: where to look first, and why.
func cmdHunt(args []string) error {
	fs := newFlags("hunt")
	db := fs.String("db", "", "workspace database (default: the last run's)")
	var roles stringsFlag
	fs.Var(&roles, "roles", "the JSONL `azhaq roles -json` printed: rows where one role reached another's data rank first (repeatable)")
	since := fs.Duration("since", 7*24*time.Hour, "first seen within this long is new: a bonus, never the reason a row ranks")
	limit := fs.Int("limit", 25, "rows at most, best first")
	asJSON := fs.Bool("json", false, "one JSON object per row, and the summary as JSON on stderr")
	if err := parse(fs, args); err != nil {
		return err
	}
	path := *db
	if path == "" {
		if path = readLastDB(); path == "" {
			return usagef("give -db FILE: %s", noLastText())
		}
	}
	if *limit < 1 {
		return usagef("-limit: need at least 1")
	}
	var rows []hunt.RoleRow
	for _, f := range roles {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		rs, err := hunt.ReadRoles(fh)
		fh.Close()
		if err != nil {
			return fmt.Errorf("-roles %s: %v", f, err)
		}
		// Rows an older roles printed carry no directory: the file's own,
		// else the newest one the roles default names.
		dir := rolesDirFor(f)
		for i := range rs {
			if rs[i].Dir == "" {
				rs[i].Dir = dir
			}
		}
		rows = append(rows, rs...)
	}
	g, err := readGraph(path)
	if err != nil {
		return err
	}
	all := huntRows(g, path, rows, *since)
	matched := len(all)
	list := all
	if len(list) > *limit {
		list = list[:*limit]
	}
	enc := json.NewEncoder(os.Stdout)
	tiers := countRows(list)
	tier := ""
	for _, r := range list {
		if *asJSON {
			if err := enc.Encode(r); err != nil {
				return err
			}
			continue
		}
		if r.Tier != tier {
			// Findings first, then the identifications, then the leads, each with the check that would prove it.
			tier = r.Tier
			switch tier {
			case "finding":
				fmt.Printf("findings (%d): proven, the answer shows the thing named\n", tiers.Findings)
			case "identification":
				fmt.Printf("identifications (%d): what the run named on each listener; the label says how far a read settled the advisory (version-only: the version is in range, nothing checked)\n", tiers.Identifications)
			default:
				fmt.Printf("leads (%d): inferred from a name, a path or a guess; each names the check that would prove it\n", tiers.Leads)
			}
		}
		parts := make([]string, len(r.Reasons))
		for i, x := range r.Reasons {
			parts[i] = x.Signal + ": " + x.Detail
		}
		line := fmt.Sprintf("%3d  %3d  %s  %s", r.Rank, r.Score, r.Key, strings.Join(parts, "; "))
		if r.Tier == "lead" {
			line += "  → check: " + r.Check
		}
		fmt.Printf("%s  → next: %s\n", line, r.Next)
	}
	rep := newReport("hunt")
	rep.what = "rows"
	rep.Results = len(list)
	rep.DB = path
	rep.Tiers = &tiers
	if matched > len(list) {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d rows have a signal (%s); -limit %d printed the first %d (best first), %d are left out: -limit %d prints them all",
			matched, countRows(all), *limit, len(list), matched-len(list), matched))
	}
	if len(roles) == 0 && signedWorkspace(path) {
		rep.hint(rolesHint)
	}
	return rep.finish(*asJSON, false)
}

// huntRows ranks a workspace's surface, best first and before any -limit: the
// routes and hosts the map holds, and what the run named on each listener (the
// records of `report -findings`, one row for each listener and product).
func huntRows(g *graphView, path string, roles []hunt.RoleRow, since time.Duration) []hunt.Row {
	in := hunt.Input{DB: path, Rows: g.rows, Obs: g.obs, Roles: roles, Now: time.Now(), Since: since}
	for _, s := range secretRows(g.obs) {
		in.Secrets = append(in.Secrets, hunt.Secret{Kind: s.Kind, Severity: s.Severity, Where: s.Where, Name: s.Name, Preview: s.Redacted, Rule: s.Rule, Entropy: s.Entropy,
			Known: s.Rule == "known key format" && s.Severity != "info"})
	}
	ents := make([]types.Entity, 0, len(g.rows))
	for _, r := range g.rows {
		ents = append(ents, r.Entity)
	}
	for _, t := range takeovers(ents, g.obs) {
		in.Takeovers = append(in.Takeovers, hunt.Takeover{Host: t.Host, Strong: t.Strength == "strong", Dangling: t.Strength == "dangling", Detail: takeoverDetail(t.Finding)})
	}
	set := buildFindings(g)
	in.Listeners = listenersOf(set)
	for _, r := range set.Findings {
		if r.Kind == danglingKind {
			in.Measured = append(in.Measured, hunt.Measured{Kind: r.Kind, Host: r.Host, Severity: r.Severity, Evidence: r.Evidence, Command: r.Command, Proof: r.Proof})
		}
	}
	return hunt.Build(in)
}

// listenersOf are the listener rows of a findings set: each listener's
// identification for each product, from its best record (a read's label before
// a range match, the exploited and best scored advisory first: the order the
// set is already in), with how many advisories the version matches; and the
// findings a read proved on a listener. Nothing here is a record the findings
// output does not list.
func listenersOf(set findingSet) []hunt.Listener {
	var out []hunt.Listener
	toListener := func(r findingRecord, kind string) hunt.Listener {
		return hunt.Listener{Ident: hunt.Ident{Kind: kind, What: r.Kind, Host: r.Host, Port: r.Port, Product: r.Product, Version: r.Version, Source: r.Source,
			AdvisoryID: r.AdvisoryID, AdvisoryURL: r.AdvisoryURL, Label: r.Label, Severity: r.Severity, KEV: r.KEV, CVSS: r.CVSS,
			Evidence: r.Evidence, Command: r.Command}, Proof: r.Proof}
	}
	for _, r := range set.Findings {
		if r.Collector == "azhaq-verify" {
			out = append(out, toListener(r, proof.TierFinding))
		}
	}
	at := map[string]int{}
	for _, r := range set.Identifications {
		k := targetOf(r) + "\x00" + advisory.ProductKey(r.Product)
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			out = append(out, toListener(r, proof.TierIdentification))
			i = at[k]
		}
		if r.AdvisoryID != "" {
			out[i].Advisories++
		}
	}
	return out
}

// huntLine is the next line a run names first: hunt, with the rows it shows.
func huntLine(db string, rows []hunt.Row) string {
	c := countRows(rows)
	return fmt.Sprintf("azhaq hunt -db %s   (%s, %s, %s)", db, plural(c.Findings, "finding"), plural(c.Identifications, "identification"), plural(c.Leads, "lead"))
}

// countRows counts rows by tier.
func countRows(rows []hunt.Row) tierCounts {
	var c tierCounts
	for _, r := range rows {
		switch r.Tier {
		case proof.TierFinding:
			c.Findings++
		case proof.TierIdentification:
			c.Identifications++
		default:
			c.Leads++
		}
	}
	return c
}

// rolesDirFor finds the directory of the roles run behind a -roles file
// that does not name it: the file's own folder when it holds roles.db,
// else the newest azhaq-roles-* folder of the current directory that does.
func rolesDirFor(file string) string {
	holds := func(dir string) bool {
		st, err := os.Stat(filepath.Join(dir, evidenceFile))
		return err == nil && !st.IsDir()
	}
	abs := func(dir string) string {
		if a, err := filepath.Abs(dir); err == nil {
			return a
		}
		return dir
	}
	if d := filepath.Dir(file); holds(d) {
		return abs(d)
	}
	dirs, _ := filepath.Glob("azhaq-roles-*")
	sort.Strings(dirs) // the names end in a timestamp
	for i := len(dirs) - 1; i >= 0; i-- {
		if holds(dirs[i]) {
			return abs(dirs[i])
		}
	}
	return ""
}

func takeoverDetail(f takeover.Finding) string {
	if f.Strength == "dangling" {
		// What the claim rests on, and where to check it.
		return "unverified: NXDOMAIN does not show the name is free: " + f.Service + " candidate, CNAME " + f.Target + " does not resolve (" + f.List + ")"
	}
	d := f.Service + " takeover, " + f.Strength + ", " + f.Settled().Status
	if f.Target != "" {
		d += ": CNAME " + f.Target
	}
	if f.Evidence != "" {
		d += " (" + f.Evidence + ")"
	}
	return d
}
