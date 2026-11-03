package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/types"
)

// A findings record is one row of `azhaq report -findings` (and of
// `azhaq export -format findings`/`findings-md`): one record per
// stored row whose label supports it, never more than the row holds.
// The labels are the verification labels of internal/verify — proved
// first, version-only and conditional kept distinct, never merged
// into proved — and a record carries the kind, the severity, the
// host, port and URL, the product and version where confirmed, the
// advisory id where matched, an excerpt of the evidence, and the
// command that produced it. A row that proves nothing (a map hint) is
// a lead, listed separately, never among the findings.
type findingRecord struct {
	Kind         string `json:"kind"`
	Label        string `json:"label"` // proved, version-only, conditional; lead for a lead
	Severity     string `json:"severity"`
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	URL          string `json:"url,omitempty"`
	Product      string `json:"product,omitempty"`
	Version      string `json:"version,omitempty"`
	AdvisoryID   string `json:"advisory_id,omitempty"`
	AdvisoryURL  string `json:"advisory_url,omitempty"`
	Precondition string `json:"precondition,omitempty"`
	Request      string `json:"request,omitempty"`
	Evidence     string `json:"evidence"`
	Command      string `json:"command"`
	Collector    string `json:"collector,omitempty"` // the collector of the stored row this record is read from
}

// runCommand is the command that produced a workspace's rows, as the
// workspace recorded it: azhaq and the run's stored options (taken of
// anything secret when they were stored). A stored verify row's own
// command is more exact and wins where a record is read from one.
func runCommand(g *graphView) string {
	if len(g.args) == 0 {
		return ""
	}
	return "azhaq " + strings.Join(g.args, " ")
}

var labelRank = map[string]int{verify.Proved: 0, verify.VersionOnly: 1, verify.Conditional: 2}

// buildFindings reads a workspace's findings and leads from its
// stored rows: the verify rows a -verify run stored, the advisory
// leads a -advisories run stored (labelled as internal/verify labels
// them; a verify row covers its own lead, so no lead is recorded
// twice), and the map's hint rows as leads. Counts in every rendering
// are the lengths of these two lists: derivable by counting the
// stored rows of those collectors, and the hint rows of the map.
func buildFindings(g *graphView) (findings, leads []findingRecord) {
	command := runCommand(g)
	covered := map[string]bool{} // advisory id + target a verify row already records
	for _, r := range verifyResultsOf(g.obs) {
		rec := findingRecord{
			Kind: r.Kind, Label: r.Label, Severity: r.Severity, Host: r.Host, Port: r.Port,
			URL: r.URL, Product: r.Product, Version: r.Version, AdvisoryID: r.AdvisoryID,
			AdvisoryURL: r.AdvisoryURL, Precondition: r.Precondition, Request: r.Request,
			Evidence: r.Evidence, Command: r.Command, Collector: "azhaq-verify",
		}
		if rec.Command == "" {
			rec.Command = command
		}
		if rec.AdvisoryID != "" {
			covered[rec.AdvisoryID+"|"+r.Target] = true
		}
		findings = append(findings, rec)
	}
	for _, lead := range advisoryLeadsOf(g.obs) {
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
		findings = append(findings, findingRecord{
			Kind: r.Kind, Label: r.Label, Severity: r.Severity, Host: r.Host, Port: r.Port,
			URL: r.URL, Product: r.Product, Version: r.Version, AdvisoryID: r.AdvisoryID,
			AdvisoryURL: r.AdvisoryURL, Precondition: r.Precondition, Request: r.Request,
			Evidence: r.Evidence, Command: command, Collector: "azhaq-advisories",
		})
	}
	for _, row := range g.rows {
		if row.Entity.Type != types.TypeURL || row.Coverage != "hint" {
			continue
		}
		rec := findingRecord{Kind: "hint", Label: "lead", Severity: "info", URL: row.Entity.Key,
			Evidence: row.Proof, Command: command}
		if rec.Evidence == "" {
			rec.Evidence = row.Evidence
		}
		if u, err := url.Parse(row.Entity.Key); err == nil {
			rec.Host = u.Hostname()
			if p, err := strconv.Atoi(u.Port()); err == nil {
				rec.Port = p
			}
		}
		leads = append(leads, rec)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := labelRank[a.Label], labelRank[b.Label]; ra != rb {
			return ra < rb
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		return a.URL < b.URL
	})
	sort.SliceStable(leads, func(i, j int) bool { return leads[i].URL < leads[j].URL })
	return findings, leads
}

// findingLine is a record as one JSONL line, typed so a reader can
// tell a finding from a lead without reading the label.
type findingLine struct {
	Type string `json:"type"`
	findingRecord
}

// findingsJSONL is the findings as JSON Lines: one finding per line,
// then one lead per line. An empty set is one explicit line saying
// so, so a pipeline reading the output can tell "no qualifying rows"
// from a broken export.
func findingsJSONL(findings, leads []findingRecord) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if len(findings) == 0 && len(leads) == 0 {
		_ = enc.Encode(struct {
			Type     string `json:"type"`
			Findings int    `json:"findings"`
			Leads    int    `json:"leads"`
		}{"findings", 0, 0})
		return b.Bytes()
	}
	for _, f := range findings {
		_ = enc.Encode(findingLine{Type: "finding", findingRecord: f})
	}
	for _, l := range leads {
		_ = enc.Encode(findingLine{Type: "lead", findingRecord: l})
	}
	return b.Bytes()
}

// findingsMarkdown is the findings as Markdown: a section per label,
// proved first, and the leads apart under their own heading. An empty
// set says so in words, with the counts at zero.
func findingsMarkdown(findings, leads []findingRecord) []byte {
	var b strings.Builder
	b.WriteString("# Findings\n\n")
	if len(findings) == 0 && len(leads) == 0 {
		b.WriteString("No qualifying rows: the workspace holds no verify result and no advisory lead a label supports, and no unproved hint. 0 findings, 0 leads.\n")
		return []byte(b.String())
	}
	fmt.Fprintf(&b, "%s and %s, each read from a stored row of the workspace; proved names the read that settled it, version-only the product and version alone, conditional a precondition the read did not show.\n\n",
		plural(len(findings), "finding"), plural(len(leads), "lead"))
	for _, label := range []string{verify.Proved, verify.VersionOnly, verify.Conditional} {
		var rs []findingRecord
		for _, f := range findings {
			if f.Label == label {
				rs = append(rs, f)
			}
		}
		if len(rs) == 0 {
			continue
		}
		title := map[string]string{verify.Proved: "Proved", verify.VersionOnly: "Version-only", verify.Conditional: "Conditional"}[label]
		fmt.Fprintf(&b, "## %s (%d)\n\n", title, len(rs))
		for _, r := range rs {
			b.WriteString(findingMarkdown(r))
		}
		b.WriteString("\n")
	}
	if len(leads) > 0 {
		b.WriteString("## Leads — unproved hints\n\n")
		b.WriteString("Hints the run did not prove: a route or service something named but no read settled. They are leads to look at, not findings.\n\n")
		for _, r := range leads {
			b.WriteString(findingMarkdown(r))
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// findingMarkdown is one record as a Markdown bullet: the severity,
// what and where it is, what settles it, and the command that
// produced it.
func findingMarkdown(r findingRecord) string {
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
	if r.AdvisoryID != "" {
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
	return b.String()
}
