package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/collectors/dirscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/takeover"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// report is what every command prints last, on stderr: what came out,
// what failed, what was left alone and why, and whether the work is
// complete. With -json it is one JSON object with "type":"summary".
type report struct {
	Type        string           `json:"type"`
	Command     string           `json:"command"`
	Version     string           `json:"version"`
	Complete    bool             `json:"complete"`
	Exit        int              `json:"exit"`
	Results     int              `json:"results"`
	LeftOut     int              `json:"left_out,omitempty"` // run -no-catchall: stored rows left out of the output and of results
	Stored      int              `json:"stored,omitempty"`   // run: the map rows the database holds, before templates fold; the counts add up to it
	Folded      *int             `json:"folded,omitempty"`   // run: stored rows a printed row holds (templated URLs, dead names): results + folded + left_out = stored
	Counts      map[string]int   `json:"counts,omitempty"`
	Seconds     float64          `json:"seconds"`
	Requests    int64            `json:"requests"`              // sent to targets
	DNSQueries  int64            `json:"dns_queries,omitempty"` // sent to resolvers, retries and wildcard probes included; the ledger's dns lines
	DB          string           `json:"db,omitempty"`
	RunID       string           `json:"run_id,omitempty"`
	Unreachable []string         `json:"unreachable,omitempty"`
	Failures    int              `json:"failures"` // the sum of count over failed, plus unreachable targets it does not name: see decide
	Failed      []engine.Failure `json:"failed,omitempty"`
	Skipped     []engine.Skip    `json:"skipped,omitempty"`
	Takeover    []takeoverRow    `json:"takeover,omitempty"`    // names another party may take over
	Degraded    bool             `json:"degraded,omitempty"`    // a source the run depends on failed (subs); the exit code is 3
	DegradedBy  []degradedBy     `json:"degraded_by,omitempty"` // with degraded: each failed source, its reason and how many domains
	Junk        map[string]int   `json:"junk,omitempty"`        // urls: URLs left out as junk, by reason (-raw keeps them)
	Sources     *sourceHealth    `json:"sources,omitempty"`     // subs and urls: how many sources answered, which failed and why, what each gave
	Stopped     string           `json:"stopped,omitempty"`     // the limit that stopped the work
	Resume      string           `json:"resume,omitempty"`
	Notes       []string         `json:"notes,omitempty"`
	Next        []string         `json:"next,omitempty"`
	Error       string           `json:"error,omitempty"` // an internal error: the summary disagrees with its rows (audit.go); exit 1
	// Cost is what the run was estimated to send before it started, by
	// stage, beside what each stage sent (see cost.go).
	Cost *costReport `json:"cost,omitempty"`
	// Advisories are the -advisories leads: one per stored advisory row,
	// each with its advisory id and URL, its match label and, when a
	// confirmation ran, its confidence. They are leads, not map rows:
	// Counts still adds up to Stored without them, and the notes say
	// how their counts are derived (one lead per line printed).
	Advisories []advisory.Lead `json:"advisories,omitempty"`
	// Verify are the -verify results: one per stored verify row, each
	// labelled proved, version-only or conditional with the exact
	// request sent and an excerpt of the answer. Like the advisory
	// leads they are not map rows: Counts still adds up to Stored
	// without them, and the notes say how their counts are derived.
	Verify []verify.Result `json:"verify,omitempty"`

	estimate  *costEstimate             // what the command was estimated to send, for Cost
	dnsFrom   int64                     // egress.DNSTotal when the command began: dns_queries are its own
	spentFrom map[ledger.SpentKey]int64 // ledger.Account when it began: the cost is what it sent since

	what string // the unit of Results: "names", "web services"

	// What the summary is audited against (audit.go): the rows the command
	// emitted, the counts of rows it left out, the identities it states and the
	// disagreements found.
	rows      *tally
	leftOutBy map[string]int
	sums      []sum
	problems  []string
	audited   bool

	warned bool // a note says the results mislead (a role's dead session): exit 3
	// failedRows, when set, is `failures`: probe counts its rows without an answer.
	failedRows *int
	targets    targetTally // the targets the run was given and how many of them got no answer (exit.go)

	noCatchAll bool // run -no-catchall: its rows of the catch-all page are left out of results
	start      time.Time

	// hints are measured suggestions, printed as "next:" lines for a person
	// (see hints.go); they are never in the JSON summary.
	hints              []string
	late               []func() string
	hintsOff, hintsVrb bool

	hushCost  bool     // an embedded run: the command that owns it says the cost
	refusedBy []string // run: the collectors whose work the request budget refused, first first
}

func newReport(command string) *report {
	return &report{Type: "summary", Command: command, Version: version, start: time.Now(), dnsFrom: egress.DNSTotal(), spentFrom: ledger.Account()}
}

// settle fills the exit code and seconds.
func (r *report) settle() {
	if r.start.IsZero() {
		r.start = time.Now()
	}
	r.Seconds = float64(time.Since(r.start).Milliseconds()) / 1000
	r.DNSQueries = egress.DNSTotal() - r.dnsFrom
	r.Failures = r.failureCount()
	r.audit()
	switch {
	case len(r.problems) > 0:
		r.Error = r.internalError()
		r.Exit = exitError
	case r.Stopped != "":
		r.Exit = exitLimit
	default:
		r.Exit = r.decide()
	}
	r.Complete = r.Exit == exitOK
}

// err is the command's result for main: nil, or the exit code the
// summary explained.
func (r *report) err() error {
	if r.Exit == exitOK {
		return nil
	}
	if r.Error != "" {
		return exitErr{code: r.Exit, msg: r.Error}
	}
	return exitErr{code: r.Exit}
}

// finish prints the summary: always with asJSON, otherwise unless silent
// and complete. It returns the command's error.
func (r *report) finish(asJSON, silent bool) error {
	r.settle()
	r.hintsOff = r.hintsOff || asJSON || silent
	switch {
	case asJSON:
		raw, _ := json.Marshal(r)
		fmt.Fprintf(os.Stderr, "%s\n", raw)
	case silent && r.Exit == exitOK && r.Failures == 0 && (r.Sources == nil || r.Sources.failures() == 0):
		// A source that failed is something that failed: it is said under -silent too.
		// So is a takeover candidate: a finding, not a note.
		for _, t := range r.Takeover {
			fmt.Fprintln(os.Stderr, takeoverLine(t))
		}
	default:
		r.print(os.Stderr)
	}
	return r.err()
}

func (r *report) print(w io.Writer) {
	var head []string
	what := r.what
	if what == "" {
		what = "results"
	}
	head = append(head, fmt.Sprintf("%d %s", r.Results, what))
	if len(r.Counts) > 0 {
		var parts []string
		for _, k := range sortedCountKeys(r.Counts) {
			name := k
			if r.Counts[k] == 1 {
				name = countName(k)
			}
			parts = append(parts, fmt.Sprintf("%d %s", r.Counts[k], name))
		}
		list := strings.Join(parts, ", ")
		if r.LeftOut > 0 {
			list += fmt.Sprintf("; %d left out (-no-catchall)", r.LeftOut)
		}
		if r.Stored > r.Results && r.Folded != nil {
			// A templated row holds many URLs, a dead-names row many names:
			// the counts are of the stored rows, so they add up to more.
			list = fmt.Sprintf("%d stored: %s; %d folded into templated rows", r.Stored, list, *r.Folded)
		}
		head[0] += " (" + list + ")"
	}
	if r.Degraded {
		// The summary opens with it, naming the sources and why.
		d := fmt.Sprintf("DEGRADED: %d of %d sources failed", r.Counts["sources failed"], r.Counts["sources asked"])
		if len(r.DegradedBy) > 0 {
			d += ": " + degradedText(r.DegradedBy)
		}
		head = append([]string{d + ", the names may be incomplete"}, head...)
	}
	if r.Requests > 0 {
		head = append(head, fmt.Sprintf("%d requests", r.Requests))
	}
	if r.DNSQueries > 0 {
		head = append(head, fmt.Sprintf("%d DNS queries", r.DNSQueries))
	}
	head = append(head, fmt.Sprintf("%.1f s", r.Seconds))
	if r.DB != "" {
		head = append(head, "db "+r.DB)
	}
	fmt.Fprintf(w, "azhaq %s: %s\n", r.Command, strings.Join(head, " · "))
	for _, u := range r.Unreachable {
		fmt.Fprintf(w, "  ! did not answer: %s\n", u)
	}
	for i, f := range r.Failed {
		if i == 8 {
			fmt.Fprintf(w, "  ! … %d more kinds of failure (-json lists them)\n", len(r.Failed)-8)
			break
		}
		who := f.Collector
		if f.Source != "" {
			who += " source " + f.Source
		}
		line := fmt.Sprintf("  ! %s failed: %s", who, f.Error)
		if f.Count > 1 {
			line += fmt.Sprintf(" ×%d", f.Count)
		}
		if len(f.Targets) > 0 {
			line += " (" + strings.Join(f.Targets[:min(len(f.Targets), 2)], ", ")
			if f.Count > 2 {
				line += ", …"
			}
			line += ")"
		}
		var tags []string
		if f.Retryable {
			tags = append(tags, "retryable")
		}
		if f.Fanout {
			tags = append(tags, "fan-out, not your target")
		}
		if f.Partial && !f.Fanout {
			tags = append(tags, "other sources answered")
		}
		if len(tags) > 0 {
			line += " [" + strings.Join(tags, "; ") + "]"
		}
		fmt.Fprintln(w, line)
	}
	if len(r.Skipped) > 0 {
		byReason := map[string][]string{}
		var reasons []string
		for _, s := range r.Skipped {
			if _, ok := byReason[s.Reason]; !ok {
				reasons = append(reasons, s.Reason)
			}
			byReason[s.Reason] = append(byReason[s.Reason], s.Target)
		}
		for _, why := range reasons {
			ts := byReason[why]
			line := fmt.Sprintf("  - not requested, %s: %s", why, strings.Join(ts[:min(len(ts), 3)], ", "))
			if len(ts) > 3 {
				line += fmt.Sprintf(" and %d more", len(ts)-3)
			}
			fmt.Fprintln(w, line)
		}
	}
	for _, t := range r.Takeover {
		line := fmt.Sprintf("  ! takeover candidate (%s): %s · %s", t.Strength, t.Host, t.Evidence)
		if t.List != "" {
			line += " [" + t.List + "]"
		}
		fmt.Fprintln(w, line)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
	if r.Cost != nil && !r.hushCost && (r.Command == "run" || r.Command == "roles") {
		for _, l := range r.Cost.lines() {
			fmt.Fprintf(w, "  cost: %s\n", l)
		}
	}
	if r.Stopped != "" {
		line := "  stopped: " + r.Stopped
		if r.Resume != "" {
			line += "; " + r.Resume + " continues"
		}
		fmt.Fprintln(w, line)
	}
	for _, n := range r.Next {
		fmt.Fprintf(w, "  next: %s\n", n)
	}
	for _, h := range r.shownHints() {
		fmt.Fprintf(w, "  next: %s\n", h)
	}
	if r.Sources != nil && r.Sources.failures() > 0 {
		fmt.Fprintf(w, "  %s\n", r.Sources.line(r.Exit, r.Command == "urls"))
	}
	switch r.Exit {
	case exitError:
		if r.Error != "" {
			fmt.Fprintf(w, "  ERROR: %s\n", r.Error)
		}
	case exitOK:
		if r.hasFailure() {
			fmt.Fprintf(w, "  exit 0: %s; the results are usable (-strict-exit makes any failure exit 3)\n", r.doneWith())
		}
	case exitPartial:
		fmt.Fprintf(w, "  exit 3: %s\n", r.failedBecause())
	case exitLimit:
		fmt.Fprintf(w, "  exit 4: stopped by a limit with work left\n")
	}
}

func sortedCountKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// runEmbedded maps with args for a command built on run (watch, roles):
// no map on stdout, the run's summary on stderr. Failures and limits are
// in the summary it returns, not errors.
func runEmbedded(args []string) (*report, error) {
	return runEmbeddedAs(args, false)
}

// runEmbeddedAs is runEmbedded with the summary as one JSON line when
// asJSON is set.
func runEmbeddedAs(args []string, asJSON bool) (*report, error) {
	rep := newReport("run")
	out := runOut{embedded: true}
	if err := mapTarget(args, rep, &out); err != nil {
		return nil, err
	}
	rep.settle()
	if asJSON {
		raw, _ := json.Marshal(rep)
		fmt.Fprintf(os.Stderr, "%s\n", raw)
	} else {
		rep.print(os.Stderr)
	}
	return rep, nil
}

// fillReport adds what a run's database says to rep: failures, skips,
// targets that did not answer, notes and counts.
func fillReport(rep *report, path string, seeds []types.Seed, ents []types.Entity, obs []types.StoredObservation, rows []engine.MapEntry) {
	rep.DB = path
	rep.Failed = engine.MarkPartial(engine.MarkFanout(engine.Failures(ents, obs), seeds), ents, obs)
	rep.Skipped = append(rep.Skipped, engine.Skips(ents, obs)...)
	if n := len(retried); n > 0 {
		now := map[string]bool{}
		for _, f := range engine.FailedTargets(ents, obs) {
			now[f.Collector+"\x00"+f.Target] = true
		}
		still := 0
		for _, f := range retried {
			if now[f.Collector+"\x00"+f.Target] {
				still++
			}
		}
		retried = nil
		rep.Notes = append(rep.Notes, fmt.Sprintf("-retry-failed: %d failed targets of run %s asked again, %d still fail (azhaq query -db %s -failed -run %s lists them)", n, retriedRun, still, path, retriedRun))
	}
	rep.Unreachable = engine.Unreachable(seeds, ents, obs)
	rep.targets = tallySeeds(rep.Command, seeds, rep.Unreachable, rep.Failed)
	rep.Notes = append(rep.Notes, engine.Notes(obs)...)
	rep.Notes = append(rep.Notes, portcol.Notes(obs)...)
	if rep.Command == "run" {
		rep.Notes = append(rep.Notes, historyNotes(subdomainPayloads(obs))...)
	}
	if n := engine.NoWebNote(obs); n != "" {
		rep.Notes = append(rep.Notes, n)
	}
	if n := engine.NotHTTPNote(obs); n != "" {
		rep.Notes = append(rep.Notes, n)
	}
	rep.Notes = append(rep.Notes, engine.CatchAllNotes(rows)...)
	rep.Notes = append(rep.Notes, engine.CatchAllHeldNotes(rows, obs)...)
	rep.Notes = append(rep.Notes, portcol.StoppedNotes()...)
	rep.Notes = append(rep.Notes, engine.GraphQLNotes(obs)...)
	rep.Notes = append(rep.Notes, pathscol.Notes(obs)...)
	if notes, loose := dirscol.Notes(obs); len(notes) > 0 {
		rep.Notes = append(rep.Notes, notes...)
		rep.warned = rep.warned || loose // wildcard answers among the paths: not a calibrated list
	}
	rep.Notes = append(rep.Notes, fetch.Notes()...)
	if partialShots(obs) {
		rep.warned = true // a picture short of its page is not a result to take as whole
	}
	rep.Notes = append(rep.Notes, pageFaultNotes(obs)...)
	rep.Notes = append(rep.Notes, interactNotes(obs)...)
	rep.Takeover = takeovers(ents, obs)
	if path != "" && !strings.HasPrefix(path, os.TempDir()) && len(rep.Failed) > 0 {
		rep.Next = append(rep.Next, "azhaq query -db "+path+" -failed   (every failed target, the list to retry)")
	}
	if rep.Command != "run" {
		return // the command counts its own results
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[countKey(r)]++
	}
	// What run prints is what results counts: with -no-catchall the rows
	// that answered with the catch-all page, or were not asked for it, are
	// stored and counted, and left out of both the output and results.
	shown := rows
	if rep.noCatchAll {
		shown = withoutCatchAll(rows, engine.CatchAllHeldIDs(obs))
	}
	rep.Results = len(engine.GroupTemplates(shown))
	if rep.noCatchAll {
		shownBy := map[string]int{}
		for _, r := range shown {
			shownBy[countKey(r)]++
		}
		rep.leftOutBy = map[string]int{}
		for k, n := range counts {
			if d := n - shownBy[k]; d > 0 {
				rep.leftOutBy[k] = d
			}
		}
	}
	folded := len(shown) - rep.Results
	rep.Folded = &folded
	rep.Stored = len(rows)
	rep.LeftOut = len(rows) - len(shown)
	rep.what = "map rows"
	rep.Counts = counts
	if hint := engine.BrowserHint(rows, obs); hint != "" {
		rep.Next = append(rep.Next, hint)
	}
	if path == "" {
		return
	}
	if counts["auth"]+counts["forbidden"] > 0 {
		rep.Next = append(rep.Next, "azhaq query -db "+path+" -role auth,forbidden   (what needs a session)")
	}
	if counts["api"] > 0 {
		rep.Next = append(rep.Next, "azhaq query -db "+path+" -role api -fields key,methods,params,body",
			"azhaq export -db "+path+" -format openapi > api.json   (for Burp, Postman, ZAP)")
	}
	if counts["auth"] > 0 {
		rep.Next = append(rep.Next, "azhaq roles -role anon -role 'user=Authorization: Bearer …' -- RUN FLAGS   (who may read what)")
	}
}

// countKey is the one count a stored map row belongs to: the counts of a
// run are disjoint and cover every row, so they add up to Stored. Each key
// is a `query` filter (docs/OUTPUT.md lists them).
func countKey(r engine.MapEntry) string {
	switch r.Entity.Type {
	case types.TypeURL:
		switch r.Coverage {
		case "catchall":
			return "catchall" // the page every unknown path gets: apart from the kind of URL it is named as
		case "skipped":
			return "skipped" // named and not asked: a -deny-path rule, or an origin that answers every path alike
		}
		switch r.Role {
		case "api", "auth", "forbidden":
			return r.Role
		case "websocket":
			return "websockets"
		case "client-route":
			return "client routes"
		case "script":
			return "scripts"
		case "asset":
			return "assets"
		case "sourcemap":
			return "source maps"
		case "manifest":
			return "manifests"
		}
		return "pages"
	case types.TypeHostname:
		switch r.Role {
		case "dead", "wildcard":
			return r.Role + " hostnames"
		}
		return "hostnames"
	case types.TypePort:
		if r.State == "open|filtered" {
			return "open|filtered ports"
		}
		return "ports"
	case types.TypeIPAddress:
		return "addresses"
	case types.TypeDomain:
		return "domains"
	case types.TypeOrganization:
		return "organizations"
	case types.TypePrefix:
		return "prefixes"
	case types.TypeCloudAccount:
		return "cloud accounts"
	}
	return strings.ToLower(string(r.Entity.Type)) + "s"
}

// countName is a count's name for one: "1 websocket", "1 address".
func countName(k string) string {
	switch {
	case k == "api" || k == "auth" || k == "forbidden":
		return k
	case strings.HasSuffix(k, "sses") || strings.HasSuffix(k, "xes"):
		return strings.TrimSuffix(k, "es")
	}
	return strings.TrimSuffix(k, "s")
}

// mapRowJSON is one row of the map for -json output and azhaq query.
func mapRowJSON(r engine.MapEntry) map[string]any {
	key := r.Entity.Key
	if r.Count > 1 {
		key = r.Template
	}
	row := map[string]any{"type": r.Entity.Type, "key": key, "scope": r.Scope}
	set := func(k string, v any, ok bool) {
		if ok {
			row[k] = v
		}
	}
	set("coverage", r.Coverage, r.Coverage != "")
	set("role", r.Role, r.Role != "")
	set("status", r.Status, r.Status != 0)
	set("answer", r.Answer, r.Answer != "")
	set("evidence", r.Evidence, r.Evidence != "")
	set("evidence_from", r.EvidenceFrom, len(r.EvidenceFrom) > 0)
	set("response_file", r.ResponseFile, r.ResponseFile != "" && r.Count <= 1)
	set("title", r.Title, r.Title != "")
	set("state", r.State, r.State != "")
	set("names", r.Names, len(r.Names) > 0)
	set("service", r.Service, r.Service != "")
	set("product", r.Product, r.Product != "")
	set("version", r.Version, r.Version != "")
	set("methods", r.Methods, len(r.Methods) > 0)
	set("params", r.Params, len(r.Params) > 0)
	set("body", r.Body, len(r.Body) > 0)
	set("ops", r.Ops, len(r.Ops) > 0)
	set("forms", r.Forms, len(r.Forms) > 0)
	set("found_in", r.Found, len(r.Found) > 0)
	w := engine.Watch(r)
	set("watch", w, len(w) > 0)
	set("guard", r.Guard, r.Guard != "")
	set("protocol", r.Protocol, r.Protocol != "")
	set("namespace", r.Namespace, r.Namespace != "")
	set("template", r.Template, r.Template != "")
	set("count", r.Count, r.Count > 1)
	set("not_asked", r.NotAsked, r.NotAsked > 0)
	set("capped", r.Capped, r.Capped > 0)
	set("folded", r.Folded, r.Folded > 0)
	set("proof", r.Proof, r.Proof != "")
	set("first_seen", r.Entity.FirstSeen.UTC().Format(time.RFC3339), !r.Entity.FirstSeen.IsZero())
	return row
}

// progressMode says how a command that works for long reports it on stderr:
// "" for none (-quiet, unless -v), "json" with -json, else "text". forced is
// what a drop-in decided for itself ("json" for its -json).
func progressMode(quiet, verbose, asJSON bool, forced string) string {
	switch {
	case forced != "":
		return forced
	case quiet && !verbose:
		return ""
	case asJSON:
		return "json"
	}
	return "text"
}

// stillWaiting names the subdomain sources that have not answered, for the
// progress line: a run held by one (crt.sh on a large domain) says so.
func stillWaiting() string {
	ws := subcol.Waiting()
	if len(ws) == 0 {
		return ""
	}
	var parts []string
	for i, w := range ws {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("%d more", len(ws)-3))
			break
		}
		p := fmt.Sprintf("%s (%s", w.Source, w.Longest.Round(time.Second))
		if w.Domains > 1 {
			p += fmt.Sprintf(", %d domains", w.Domains)
		}
		parts = append(parts, p+")")
	}
	return "; still waiting for " + strings.Join(parts, ", ") + " (-source-timeout bounds each source)"
}

// takeoverLine is a candidate as -silent prints it on stderr, one per line:
// [takeover] name -> cname (service, strength).
func takeoverLine(t takeoverRow) string {
	line := "[takeover] " + t.Host
	if t.Target != "" {
		line += " -> " + t.Target
	}
	return line + " (" + t.Service + ", " + t.Strength + ")"
}

// takeoverRow is a name another party may take over, and why.
type takeoverRow struct {
	Host string `json:"host"`
	takeover.Finding
}

// takeovers are the names whose DNS answer (a CNAME to something gone) or
// front page (a service's page for a name nobody claimed) says another
// party may take them, one each, the strongest finding kept.
func takeovers(ents []types.Entity, obs []types.StoredObservation) []takeoverRow {
	keys := map[string]string{}
	for _, e := range ents {
		keys[e.ID] = e.Key
	}
	type finding struct {
		FQDN     string            `json:"fqdn"`
		URL      string            `json:"url"`
		CNAMEs   []string          `json:"cnames"`
		Takeover *takeover.Finding `json:"takeover"`
	}
	var found []finding
	chains := map[string][]string{} // host → its CNAME chain, from DNS
	for _, o := range obs {
		if o.Collector != "azhaq-dns" && o.Collector != "azhaq-http" {
			continue
		}
		var p finding
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		if p.FQDN == "" && p.URL == "" {
			p.FQDN = normalize.Hostname(keys[o.EntityID])
		}
		if len(p.CNAMEs) > 0 {
			chains[normalize.Hostname(p.FQDN)] = p.CNAMEs
		}
		if p.Takeover != nil {
			found = append(found, p)
		}
	}
	byHost := map[string]takeoverRow{}
	for _, p := range found {
		host := normalize.Hostname(p.FQDN)
		if host == "" {
			host = normalize.HostFromURL(p.URL)
		}
		f := *p.Takeover
		if f.Strength == "page" {
			// A service's page, judged again by where DNS says the name
			// points: to that service, strong; elsewhere, nothing.
			if chain := chains[host]; len(chain) > 0 {
				var ok bool
				if f, ok = takeover.ByPage(chain, []byte(pageWords(f))); !ok {
					continue
				}
			}
		}
		if old, ok := byHost[host]; ok && old.Strength == "strong" {
			continue
		}
		byHost[host] = takeoverRow{Host: host, Finding: f}
	}
	out := make([]takeoverRow, 0, len(byHost))
	for _, t := range byHost {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// pageWords is the quoted page text a page finding rests on, to judge
// again beside a CNAME chain.
func pageWords(f takeover.Finding) string {
	if i := strings.Index(f.Evidence, `"`); i >= 0 {
		if j := strings.Index(f.Evidence[i+1:], `"`); j >= 0 {
			return f.Evidence[i+1 : i+1+j]
		}
	}
	return ""
}

// partialShots says a screenshot was taken before its page was loaded. A
// picture that is partial only because the scope blocked assets of other
// hosts is not one: the scope is the user's, and the row and a note say so.
func partialShots(obs []types.StoredObservation) bool {
	for _, o := range obs {
		if o.Collector != "azhaq-shots" || o.Kind != "screenshot" {
			continue
		}
		var p struct {
			Partial  bool
			Unloaded int
			Blocked  int
		}
		if json.Unmarshal(o.Payload, &p) == nil && (p.Unloaded > 0 || p.Partial && p.Blocked == 0) {
			return true
		}
	}
	return false
}

// interactNotes say what -interact did: the clicks made, the candidates
// not clicked (downloads, mail and phone links), the routes found and the
// writes the clicks would have sent.
func interactNotes(obs []types.StoredObservation) []string {
	var pages, clicks, skipped, routes, writes int
	threw := ""
	for _, o := range obs {
		if o.Kind != "interact" {
			continue
		}
		var p struct {
			Clicks, Skipped, Routes int
			Writes                  int `json:"writes_mapped"`
			Threw                   string
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		pages++
		clicks += p.Clicks
		skipped += p.Skipped
		routes += p.Routes
		writes += p.Writes
		if p.Clicks == 0 && threw == "" {
			threw = p.Threw
		}
	}
	if pages == 0 {
		return nil
	}
	note := fmt.Sprintf("-interact: %d clicks on %d pages found %d routes; %d downloads and mail or phone links not clicked; the %d writes the clicks tried were mapped, not sent", clicks, pages, routes, skipped, writes)
	if clicks == 0 {
		note += "; no button, link or menu showed on a page that had settled: it may draw them only after a slower answer than the page waits for, or need a sign-in (-login)"
		if threw != "" {
			note += "; a script of the page threw: " + threw
		}
	}
	return []string{note}
}

// pageFaultNotes say which pages Chrome rendered without their scripts: a
// script that failed, or that was answered with an HTML page (what an app
// server does for an address it cannot map, or a proxy that sends the
// origin the full address instead of the path), runs nothing, and the page
// draws no menu and calls no route.
func pageFaultNotes(obs []types.StoredObservation) []string {
	var pages, scripts int
	var first []string
	for _, o := range obs {
		if o.Kind != "pagefault" {
			continue
		}
		var p struct {
			Scripts []browser.ScriptFault
		}
		if json.Unmarshal(o.Payload, &p) != nil || len(p.Scripts) == 0 {
			continue
		}
		pages++
		scripts += len(p.Scripts)
		for _, s := range p.Scripts {
			if len(first) < 3 {
				first = append(first, s.URL+" "+s.Why)
			}
		}
	}
	if pages == 0 {
		return nil
	}
	return []string{fmt.Sprintf("-browser: %d scripts on %d pages did not load as JavaScript (%s), so those pages' apps could not start and Chrome saw none of their calls; ask a script by its address with curl, and through -proxy: a proxy must send the origin the path, not the full address", scripts, pages, strings.Join(first, "; "))}
}

// withoutCatchAll is the rows that did not answer with the page every
// unknown path gets, and the URLs not asked because that was the answer.
func withoutCatchAll(rows []engine.MapEntry, held map[string]bool) []engine.MapEntry {
	out := make([]engine.MapEntry, 0, len(rows))
	for _, r := range rows {
		if r.Entity.Type == types.TypeURL && (r.Coverage == "catchall" || r.Coverage == "skipped" && held[r.Entity.ID]) {
			continue
		}
		out = append(out, r)
	}
	return out
}
