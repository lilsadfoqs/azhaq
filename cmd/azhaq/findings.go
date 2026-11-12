package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// A findings record is one row of `azhaq report -findings` (and of
// `azhaq export -format findings`/`findings-md`), in one of three tiers:
//
//   - finding: a proven row. The answer azhaq received shows the thing the
//     row names (a file's own signature, a panel's own title, a data store's
//     answer to a read with no credential, a stack trace, a key of a known
//     format, a service's own page for an unclaimed name). It carries its
//     proof (internal/proof): when it was observed, the request, the excerpt
//     of the answer with its offset, the stage that found it and a command
//     that shows the same without azhaq.
//   - identification: a product and version a service stated, with the
//     advisory match where there is one, and the answer that stated it.
//   - lead: anything inferred from a name, a path or a guess, with the
//     check that would prove it.
//
// A row with no proof is never a finding. The labels of internal/verify
// (proved, version-only, conditional) stay on the rows that have one. A map
// hint is a lead, listed separately, unless the map's own view folds it (see
// foldedHint): then it is counted in the line of its fold class.
type findingRecord struct {
	Tier     string `json:"tier"` // finding, identification or lead
	Kind     string `json:"kind"`
	Label    string `json:"label"` // proved, version-only, conditional; lead for a lead
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	URL      string `json:"url,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	// Source says what named the product of an identification a name's root
	// page gave: page title, generator, header X-Powered-By, header Server or
	// technology. A title is no version: the version is only what one stated.
	Source       string   `json:"source,omitempty"`
	AdvisoryID   string   `json:"advisory_id,omitempty"`
	AdvisoryURL  string   `json:"advisory_url,omitempty"`
	Lead         string   `json:"lead,omitempty"` // an advisory record's service lead: "host:port Product"
	checked      bool     // a read that answered settled something of this advisory (observed or inferred)
	names        []string // every host string the listener answered under with this product and version
	KEV          bool     `json:"kev,omitempty"`  // CISA lists the advisory as exploited
	CVSS         float64  `json:"cvss,omitempty"` // the score the advisory's record states
	Precondition string   `json:"precondition,omitempty"`
	Request      string   `json:"request,omitempty"`
	Evidence     string   `json:"evidence"`
	Command      string   `json:"command"`
	Collector    string   `json:"collector,omitempty"` // the collector of the stored row this record is read from
	// Check is, for a lead, what would prove it.
	Check string `json:"check,omitempty"`
	// Proof: observed_at, method, target, request_bytes, status, content_type,
	// excerpt, excerpt_part, excerpt_offset, how and reproduce, on a finding and
	// on an identification that has the answer it was read from.
	*proof.Proof
}

// runCommand is the command that produced a workspace's rows, as the
// workspace recorded it: azhaq and the run's stored options (taken of
// anything secret when they were stored). A stored verify row's own
// command is more exact and wins where a record is read from one.
func runCommand(g *graphView) string {
	if len(g.args) == 0 {
		return ""
	}
	if strings.HasPrefix(g.args[0], "-") {
		// run keeps its flags alone (dns, fuzz and ingest keep their name
		// first): the command line that reproduces it names run.
		return "azhaq run " + strings.Join(g.args, " ")
	}
	return "azhaq " + strings.Join(g.args, " ")
}

var labelRank = map[string]int{verify.Proved: 0, verify.VersionOnly: 1, verify.Conditional: 2}

// findingSet is a workspace's rows in their three tiers, and the hints the
// map's view folds. Every stored row that has a record is in exactly one tier.
type findingSet struct {
	Findings        []findingRecord
	Identifications []findingRecord
	Leads           []findingRecord
	Folds           []engine.FoldGroup
}

// counts counts issues, not records. The advisory records of one service
// lead that no read settled (version-only and conditional alike: a range
// match, with a precondition named at most, never checked) are one
// identification. An advisory a read answered for, or a verify result, is
// one for each listener whatever the products or records that name it. The
// records themselves are all listed (each names its lead). CISA KEV is not a
// check: the run does not treat it as more than a range match.
func (s findingSet) counts() tierCounts {
	return tierCounts{len(s.Findings), issueCount(s.Identifications), len(s.Leads)}
}

// issueKey is what a record counts as: "" for a record that is its own issue.
func issueKey(r findingRecord) string {
	switch {
	case r.AdvisoryID == "":
		return ""
	case !r.checked && r.Lead != "":
		return "lead|" + r.Lead
	}
	return "advisory|" + targetOf(r) + "|" + r.AdvisoryID
}

func issueCount(rs []findingRecord) int {
	seen := map[string]bool{}
	n := 0
	for _, r := range rs {
		k := issueKey(r)
		if k == "" {
			n++
		} else if !seen[k] {
			seen[k] = true
			n++
		}
	}
	return n
}

// leadName is the service lead an advisory record belongs to.
func leadName(target, product string) string { return target + " " + product }

// buildFindings reads a workspace's rows into their tiers, from what the run
// stored and nothing more: the verify rows a -verify run stored, the advisory
// leads (a verify row covers its own lead, so none is recorded twice), the
// services whose product and version a stage read, the stack traces and the
// path checks' answers, the secrets the scripts carried, the names another
// party may claim, and the map's hint rows as leads, except the ones the map's
// default view folds (engine.Folder: assets no request asked for, routes only
// scripts name, 404s): those are counted by class in folds. Counts in every
// rendering are the lengths of the tiers and the folds' counts: derivable by
// counting the stored rows (leads + the folds' counts = query -type URL
// -coverage hint, for the hints).
// proves says a proved verify result of kind shows the thing named: a read
// with no credential, or a sign-in with a published default.
func proves(kind string) bool {
	switch kind {
	case verify.KindUnauthenticatedRead, verify.KindDefaultLogin, verify.KindUnauthenticatedBypass:
		return true
	}
	return false
}

func buildFindings(g *graphView) findingSet {
	command := runCommand(g)
	var set findingSet
	services := servicesByTarget(g.obs)
	addrs := advisory.NameAddrs(g.obs)
	hashes := map[string]string{} // URL → body hash, for the names whose answers are told apart
	for _, a := range proof.AnswersOf(g.obs) {
		if a.Hash != "" {
			hashes[a.URL] = a.Hash
		}
	}
	// One identification row for a listener (address and port), product and
	// version, whatever it was reached as; byListener is the row each stands on.
	listenerOf := func(host string, port int) string {
		host = strings.ToLower(host)
		if a, err := netip.ParseAddr(host); err == nil {
			host = a.Unmap().String()
		} else if a := addrs[host]; a != "" {
			host = a
		}
		return host + ":" + strconv.Itoa(port)
	}
	identKey := func(rec findingRecord) string {
		return listenerOf(rec.Host, rec.Port) + "|" + advisory.ProductKey(rec.Product) + "|" + rec.Version
	}
	byListener := map[string]int{}
	answerOf := func(rec findingRecord) string {
		if rec.Proof == nil {
			return ""
		}
		return hashes[rec.Proof.Target]
	}
	// foldedInto says an identification record is the listener's row seen under
	// another name, with the same answer, and notes the name on that row.
	foldedInto := func(rec findingRecord) bool {
		i, ok := byListener[identKey(rec)]
		if !ok {
			return false
		}
		have := &set.Identifications[i]
		if a, b := answerOf(*have), answerOf(rec); a != "" && b != "" && a != b {
			return false // another page of the same address and port: its own application
		}
		for _, n := range append([]string{rec.Host}, rec.names...) {
			if n != "" && !strings.EqualFold(n, have.Host) && !slices.ContainsFunc(have.names, func(x string) bool { return strings.EqualFold(x, n) }) {
				have.names = append(have.names, n)
			}
		}
		return true
	}
	add := func(rec findingRecord) {
		switch rec.Tier {
		case proof.TierFinding:
			set.Findings = append(set.Findings, rec)
		case proof.TierIdentification:
			set.Identifications = append(set.Identifications, rec)
			if rec.Product != "" && rec.Port > 0 {
				if _, ok := byListener[identKey(rec)]; !ok {
					byListener[identKey(rec)] = len(set.Identifications) - 1
				}
			}
		default:
			set.Leads = append(set.Leads, rec)
		}
	}
	ident := func(rec findingRecord) findingRecord {
		rec.Tier = proof.TierIdentification
		if rec.Proof == nil {
			if svc, ok := services[targetOf(rec)+"\x00"+advisory.ProductKey(rec.Product)]; ok {
				rec.Proof = identProof(svc)
				rec.Source = svc.Source
			}
		}
		return rec
	}
	covered := map[string]bool{}    // advisory id + target a verify row already records
	identified := map[string]bool{} // host:port + product a record already identifies
	for _, r := range verifyResultsOf(g.obs) {
		rec := findingRecord{
			Kind: r.Kind, Label: r.Label, Severity: r.Severity, Host: r.Host, Port: r.Port,
			URL: r.URL, Product: r.Product, Version: r.Version, AdvisoryID: r.AdvisoryID,
			AdvisoryURL: r.AdvisoryURL, Precondition: r.Precondition, Request: r.Request,
			Evidence: r.Evidence, Command: r.Command, Collector: "azhaq-verify", Proof: r.Proof,
		}
		if r.AdvisoryID != "" {
			rec.Lead = leadName(r.Target, r.Product)
			rec.checked = r.Label == verify.Proved
		}
		if rec.Command == "" {
			rec.Command = command
		}
		if rec.AdvisoryID != "" {
			covered[rec.AdvisoryID+"|"+r.Target] = true
		}
		identified[targetOf(rec)+"\x00"+advisory.ProductKey(rec.Product)] = true
		switch {
		case proves(r.Kind) && r.Label == verify.Proved && r.Proof.Complete():
			rec.Tier = proof.TierFinding
			add(rec)
		case proves(r.Kind) && r.Label == verify.Proved:
			// Stored without its request and answer (an older azhaq): no proof, no finding.
			rec.Tier, rec.Label, rec.Check = proof.TierLead, "lead", "run the read again: "+r.Request+" on "+r.Target
			rec.Evidence = "unauthenticated read recorded without the answer that proves it; " + r.Evidence
			add(rec)
		default:
			add(ident(rec))
		}
	}
	stats := map[string]advisory.Lead{} // advisory id + target → its lead, for the flags and the score
	for _, lead := range advisoryLeadsExpanded(g.obs) {
		stats[lead.AdvisoryID+"|"+lead.Target] = lead
	}
	for i := range set.Identifications {
		if l, ok := stats[set.Identifications[i].AdvisoryID+"|"+targetOf(set.Identifications[i])]; ok && set.Identifications[i].AdvisoryID != "" {
			set.Identifications[i].KEV, set.Identifications[i].CVSS = l.KEV, l.CVSS
			set.Identifications[i].checked = set.Identifications[i].checked || l.Confidence == advisory.Observed || l.Confidence == advisory.Inferred
		}
	}
	for _, lead := range advisoryLeadsExpanded(g.obs) {
		// The request is only carried when a confirmation read was
		// actually sent, as in verifyStage.
		request := ""
		if lead.Confidence != "" {
			request = lead.ConfirmReq
		}
		r, ok := verify.AdvisoryResult(lead, request)
		if !ok || covered[r.AdvisoryID+"|"+r.Target] {
			continue
		}
		rec := findingRecord{
			Kind: r.Kind, Label: r.Label, Severity: r.Severity, Host: r.Host, Port: r.Port,
			URL: r.URL, Product: r.Product, Version: r.Version, AdvisoryID: r.AdvisoryID,
			AdvisoryURL: r.AdvisoryURL, Precondition: r.Precondition, Request: r.Request,
			Evidence: r.Evidence, Command: command, Collector: "azhaq-advisories", KEV: lead.KEV, CVSS: lead.CVSS,
			Lead: leadName(r.Target, r.Product), checked: lead.Confidence == advisory.Observed || lead.Confidence == advisory.Inferred,
			names: lead.Names,
		}
		identified[targetOf(rec)+"\x00"+advisory.ProductKey(rec.Product)] = true
		add(ident(rec))
	}
	// The services a stage read a product and version of, with no advisory
	// matched: still an identification, with the answer that stated it.
	for _, svc := range advisory.Services(g.obs) {
		k := svc.Target() + "\x00" + advisory.ProductKey(svc.Product)
		if identified[k] {
			continue
		}
		identified[k] = true
		host := svc.Host
		if host == "" {
			host = svc.IP
		}
		p := identProof(svc)
		rec := findingRecord{Tier: proof.TierIdentification, Kind: "software-version", Label: verify.VersionOnly, Severity: "info",
			Host: host, Port: svc.Port, URL: svc.Origin, Product: svc.Product, Version: svc.Version, Source: svc.Source,
			Request: p.Method + " " + p.Target, Evidence: p.Excerpt, Command: command, Collector: p.How, Proof: p, names: svc.Names}
		if foldedInto(rec) {
			continue
		}
		add(rec)
	}
	// A product a stage named with no version: an identification too, so the
	// worklist shows what the run saw on each listener. There is no advisory to
	// match without a version, and the record says so.
	for _, svc := range advisory.ServicesAnyVersion(g.obs) {
		if svc.Product == "" || svc.Version != "" {
			continue
		}
		k := svc.Target() + "\x00" + advisory.ProductKey(svc.Product)
		if identified[k] {
			continue
		}
		identified[k] = true
		host := svc.Host
		if host == "" {
			host = svc.IP
		}
		p := identProof(svc)
		rec := findingRecord{Tier: proof.TierIdentification, Kind: "software-version", Label: verify.VersionOnly, Severity: "info",
			Host: host, Port: svc.Port, URL: svc.Origin, Product: svc.Product, Source: svc.Source,
			Request: p.Method + " " + p.Target, Evidence: "no version seen: " + p.Excerpt, Command: command, Collector: p.How, Proof: p, names: svc.Names}
		if foldedInto(rec) {
			continue
		}
		add(rec)
	}
	for _, l := range certLeads(g.obs, command) {
		add(l)
	}
	for _, t := range traceFindingsOf(g.obs, command) {
		add(t)
	}
	for _, s := range secretRows(g.obs) {
		add(secretRecord(s, command))
	}
	ents := make([]types.Entity, 0, len(g.rows))
	for _, r := range g.rows {
		ents = append(ents, r.Entity)
	}
	for _, t := range takeovers(ents, g.obs) {
		add(takeoverRecord(t, command))
	}
	for _, d := range danglingRecords(g.obs, command) {
		add(d)
	}
	answered := map[string]bool{} // the URLs a path check judged
	for url, v := range proof.Judge(proof.AnswersOf(g.obs)) {
		answered[url] = true
		if rec, ok := pathRecord(v, command); ok {
			add(rec)
		}
	}
	folder := engine.NewFolder(g.obs)
	var folded []engine.MapEntry
	for _, row := range g.rows {
		if row.Entity.Type != types.TypeURL || row.Coverage != "hint" {
			continue
		}
		if folder.Class(row) != "" {
			folded = append(folded, row)
			continue
		}
		if answered[row.Entity.Key] {
			continue // a path check judged its answer
		}
		rec := findingRecord{Tier: proof.TierLead, Kind: "hint", Label: "lead", Severity: "info", URL: row.Entity.Key,
			Evidence: row.Proof, Command: command, Check: "request it and read the answer: " + proof.Curl("GET", row.Entity.Key)}
		if rec.Evidence == "" {
			rec.Evidence = row.Evidence
		}
		rec.Host, rec.Port = hostPort(row.Entity.Key)
		add(rec)
	}
	sort.SliceStable(set.Findings, func(i, j int) bool { return findingLess(set.Findings[i], set.Findings[j]) })
	sort.SliceStable(set.Identifications, func(i, j int) bool { return findingLess(set.Identifications[i], set.Identifications[j]) })
	sort.SliceStable(set.Leads, func(i, j int) bool {
		if set.Leads[i].URL != set.Leads[j].URL {
			return set.Leads[i].URL < set.Leads[j].URL
		}
		return set.Leads[i].Kind < set.Leads[j].Kind
	})
	set.Folds = folder.Groups(folded)
	return set
}

func findingLess(a, b findingRecord) bool {
	if ra, rb := labelRank[a.Label], labelRank[b.Label]; ra != rb {
		return ra < rb
	}
	if a.Host != b.Host {
		return a.Host < b.Host
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if a.KEV != b.KEV {
		return a.KEV
	}
	if a.CVSS != b.CVSS {
		return a.CVSS > b.CVSS
	}
	if a.AdvisoryID != b.AdvisoryID {
		return a.AdvisoryID < b.AdvisoryID
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.URL < b.URL
}

// foldedCount is the hints the folds stand for.
func foldedCount(folds []engine.FoldGroup) int {
	n := 0
	for _, g := range folds {
		n += g.Count
	}
	return n
}

// foldedNote is the folds as the end of a count line: ", 626 hints folded
// (beyond-depth 600, unrequested 26)", or "" when nothing folded.
func foldedNote(folds []engine.FoldGroup) string {
	if len(folds) == 0 {
		return ""
	}
	var parts []string
	for _, g := range folds {
		parts = append(parts, fmt.Sprintf("%s %d", g.Class, g.Count))
	}
	return ", " + plural(foldedCount(folds), "hint") + " folded (" + strings.Join(parts, ", ") + ")"
}

// findingLine is a record as one JSONL line, typed so a reader can tell the
// tiers apart without reading the label: finding, identification or lead.
type findingLine struct {
	Type string `json:"type"`
	findingRecord
}

// findingsJSONL is the rows as JSON Lines: one finding per line, then one
// identification per line, then one lead per line, then one {"type":"folded"}
// line for each fold class of the hints the map's view counts and does not
// list. A set with no row at all is one explicit line saying so (with the
// count folded, when there are folds), so a pipeline reading the output can
// tell "no qualifying rows" from a broken export.
func findingsJSONL(set findingSet) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if len(set.Findings)+len(set.Identifications)+len(set.Leads) == 0 {
		_ = enc.Encode(struct {
			Type            string `json:"type"`
			Findings        int    `json:"findings"`
			Identifications int    `json:"identifications"`
			Leads           int    `json:"leads"`
			Folded          int    `json:"folded,omitempty"`
		}{"findings", 0, 0, 0, foldedCount(set.Folds)})
	}
	for _, f := range set.Findings {
		_ = enc.Encode(findingLine{Type: "finding", findingRecord: f})
	}
	for _, f := range set.Identifications {
		_ = enc.Encode(findingLine{Type: "identification", findingRecord: f})
	}
	for _, l := range set.Leads {
		_ = enc.Encode(findingLine{Type: "lead", findingRecord: l})
	}
	for _, g := range set.Folds {
		_ = enc.Encode(struct {
			Type  string `json:"type"`
			Class string `json:"class"`
			Count int    `json:"count"`
			Line  string `json:"line"`
		}{"folded", g.Class, g.Count, g.Line()})
	}
	return b.Bytes()
}

// findingsMarkdown is the rows as Markdown: a Findings section, an
// Identifications section (by label), and the Leads under their own heading,
// each with its count. Under every finding and identification are the request,
// the excerpt of the answer and the command that shows it. An empty set says
// so in words, with the counts at zero.
func findingsMarkdown(set findingSet) []byte {
	var b strings.Builder
	b.WriteString("# Findings\n\n")
	rows := len(set.Findings) + len(set.Identifications) + len(set.Leads)
	if rows == 0 && len(set.Folds) == 0 {
		b.WriteString("No qualifying rows: the workspace holds no verify result, no advisory lead, no proven path answer and no unproved hint. 0 findings, 0 identifications, 0 leads.\n")
		return []byte(b.String())
	}
	if rows == 0 {
		b.WriteString("No qualifying rows: the workspace holds nothing a tier lists, and no unproved hint the map lists. 0 findings, 0 identifications, 0 leads.\n\n")
	} else {
		fmt.Fprintf(&b, "%s, each read from a stored row of the workspace. A finding is proven: its answer shows the thing named. An identification is a product and version a service stated, with the advisory match where there is one (proved names the read that settled it, version-only the product and version alone, conditional a precondition the read did not show). A lead is inferred from a name, a path or a guess, and names the check that would prove it.\n\n", set.counts())
	}
	if len(set.Findings) > 0 {
		fmt.Fprintf(&b, "## Findings (%d)\n\n", len(set.Findings))
		for _, r := range set.Findings {
			b.WriteString(findingMarkdown(r))
		}
		b.WriteString("\n")
	}
	if len(set.Identifications) > 0 {
		fmt.Fprintf(&b, "## Identifications (%d)\n\n", issueCount(set.Identifications))
		for _, label := range []string{verify.Proved, verify.VersionOnly, verify.Conditional} {
			var rs []findingRecord
			for _, f := range set.Identifications {
				if f.Label == label {
					rs = append(rs, f)
				}
			}
			if len(rs) == 0 {
				continue
			}
			title := map[string]string{verify.Proved: "Proved", verify.VersionOnly: "Version-only", verify.Conditional: "Conditional"}[label]
			fmt.Fprintf(&b, "### %s (%d)\n\n", title, issueCount(rs))
			for _, r := range groupAdvisoryFindings(rs) {
				b.WriteString(findingMarkdown(r.rec, r.ids...))
			}
			b.WriteString("\n")
		}
	}
	if len(set.Leads) > 0 {
		fmt.Fprintf(&b, "## Leads (%d)\n\n", len(set.Leads))
		b.WriteString("Inferred from a name, a path or a guess, or an answer that did not show what the name says. They are leads to look at, not findings; each names the check that would prove it.\n\n")
		for _, r := range set.Leads {
			b.WriteString(findingMarkdown(r))
		}
		b.WriteString("\n")
	}
	if len(set.Folds) > 0 {
		fmt.Fprintf(&b, "## Folded hints (%d)\n\n", foldedCount(set.Folds))
		b.WriteString("Hints the map's own view counts and does not list, for what the run's requests showed of them (`azhaq run -all-rows` and `azhaq query -coverage hint` list them). They are not leads:\n\n")
		for _, g := range set.Folds {
			fmt.Fprintf(&b, "- %s\n", g.Line())
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// findingMarkdown is one record as a Markdown bullet: the severity, what and
// where it is, what settles it, and the command that produced it; under it,
// the proof: when it was observed, the request, the excerpt of the answer
// and the command that shows it without azhaq (a lead: the check instead).
func findingMarkdown(r findingRecord, ids ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- **%s** %s", r.Severity, r.Kind)
	where := r.URL
	if where == "" {
		where = r.Host
		if r.Port != 0 {
			where += ":" + strconv.Itoa(r.Port)
		}
	}
	if where != "" {
		fmt.Fprintf(&b, " on %s", where)
	}
	if r.Product != "" {
		b.WriteString(" (" + r.Product)
		if r.Version != "" {
			b.WriteString(" " + r.Version)
		}
		b.WriteString(")")
	}
	if r.Source != "" {
		b.WriteString(", named by " + r.Source)
	}
	if len(ids) > 1 {
		// The advisories of one service and label are one bullet: the first
		// ten (exploited and best scored first), and how many more. The
		// JSON Lines of the findings list every one.
		b.WriteString(" — " + advisory.CollapseIDs(ids, findingMDIDs) + " (" + plural(len(ids), "advisory") + ")")
	} else if r.AdvisoryID != "" {
		b.WriteString(" — " + r.AdvisoryID)
	}
	if r.Precondition != "" {
		b.WriteString("; precondition: " + r.Precondition)
	}
	if r.Request != "" {
		b.WriteString("; request: " + r.Request)
	}
	b.WriteString("; evidence: " + r.Evidence)
	if r.Command != "" {
		b.WriteString("; command: " + r.Command)
	}
	b.WriteString("\n")
	if p := r.Proof; p != nil {
		fmt.Fprintf(&b, "  - observed %s by %s: %s %s", p.ObservedAt, p.How, p.Method, p.Target)
		if p.RequestBytes != "" {
			fmt.Fprintf(&b, " (request bytes `%s`)", p.RequestBytes)
		}
		b.WriteString("\n")
		at := ""
		if p.ExcerptOffset != nil {
			at = fmt.Sprintf(" at byte %d", *p.ExcerptOffset)
		}
		status := ""
		if p.Status != 0 {
			status = fmt.Sprintf("%d %s, ", p.Status, p.ContentType)
		}
		fmt.Fprintf(&b, "  - answer (%s%s%s): `%s`\n", status, p.ExcerptPart, at, strings.ReplaceAll(p.Excerpt, "`", "'"))
		fmt.Fprintf(&b, "  - reproduce: `%s`\n", p.Reproduce)
	}
	if r.Check != "" {
		fmt.Fprintf(&b, "  - check: %s\n", r.Check)
	}
	return b.String()
}

// findingMDIDs is how many advisory ids a Markdown bullet lists before "and N more".
const findingMDIDs = 10

// targetOf is the host:port of a record, as an advisory lead names its target.
func targetOf(r findingRecord) string {
	if r.Port > 0 {
		return fmt.Sprintf("%s:%d", r.Host, r.Port)
	}
	return r.Host
}

// groupedFinding is a bullet of the Markdown findings: a record, and, when
// it stands for the advisories of one service, their ids.
type groupedFinding struct {
	rec findingRecord
	ids []string
}

// groupAdvisoryFindings makes one bullet of the advisory records of one
// service (in a section of one label), in the order they come: the first
// record stands for the others, whose ids it lists.
func groupAdvisoryFindings(rs []findingRecord) []groupedFinding {
	var out []groupedFinding
	at := map[string]int{}
	for _, r := range rs {
		if r.AdvisoryID == "" {
			out = append(out, groupedFinding{rec: r})
			continue
		}
		k := r.Host + "|" + strconv.Itoa(r.Port) + "|" + r.Product + "|" + r.Version
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			out = append(out, groupedFinding{rec: r, ids: []string{r.AdvisoryID}})
			continue
		}
		out[i].ids = append(out[i].ids, r.AdvisoryID)
	}
	return out
}
