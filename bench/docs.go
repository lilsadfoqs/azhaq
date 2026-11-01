package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// docsRow is the docs-drift check: public docs must not say what the code
// stopped doing, and the README's benchmark label must name the release.
type docsRow struct {
	Hits      []string `json:"hits,omitempty"`
	ReadmeVer string   `json:"readme_version"`
	ReadmeDay string   `json:"readme_date"`
	Changelog string   `json:"changelog_version"`
	Tag       string   `json:"tag"`
	Record    string   `json:"record_date"`
}

var (
	// An active option does not need -allow or a scope: the targets given are its scope.
	needsScope = regexp.MustCompile("(?i)\\b(needs?|requires?)\\b[^.\\n|]{0,60}(`?-allow`?|\\ba scope\\b)")
	getsOnly   = regexp.MustCompile(`(?i)\bGETs?[ -]only\b|\bonly GETs?\b|\bGET requests only\b`)
	// A "GETs only" that speaks for the whole tool, not one command's replay.
	generalClaim = regexp.MustCompile(`(?i)\bsends?\b|requests? (are|is)|\bports?\b|banner|every request|all requests`)
	latestRun    = regexp.MustCompile(`Latest run \((\d{4}-\d{2}-\d{2}), v?(\d+\.\d+\.\d+)`)
	changeHead   = regexp.MustCompile(`(?m)^## v?(\d+\.\d+\.\d+)`)
)

// docLinesAllowed are lines that say a thing about a command where it is true.
var docLinesAllowed = []string{"mcp", "azhaq worker", "-serve", "unlocked", "hackerone", "program",
	"may change data", "when there is none, the targets given"} // params bodies (true: they need a named target); the scope rule stated whole

func benchDocs() *docsRow {
	row := &docsRow{}
	files := []string{"README.md"}
	more, _ := filepath.Glob("docs/*.md")
	for _, f := range more {
		if b := filepath.Base(f); b != "PLAN.md" && b != "STATUS.md" {
			files = append(files, f)
		}
	}
	pages, _ := filepath.Glob("docs/commands/*.md")
	files = append(files, pages...)
	text := map[string]string{}
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			text[f] = string(b)
		}
	}
	if out, err := exec.Command(azhaq, "help", "-json").Output(); err == nil {
		text["help -json"] = string(out)
	}
	// What a client reads besides help: a plan's sends and the MCP tools' descriptions.
	// "GETs only" in them is a claim of safety whatever else the line says.
	strict := map[string]bool{"plan -json": true, "mcp tools/list": true}
	if out, err := exec.Command(azhaq, "plan", "-url", "http://127.0.0.1:1/", "-json").Output(); err == nil {
		text["plan -json"] = string(out)
	}
	mcpDir, _ := os.MkdirTemp("", "azhaq-bench-docs-")
	defer os.RemoveAll(mcpDir)
	mcp := exec.Command(azhaq, "mcp", "-unlocked", "-dir", mcpDir)
	mcp.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bench","version":"1"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	if out, err := mcp.Output(); err == nil {
		text["mcp tools/list"] = string(out)
	}
	for _, f := range append(files, "help -json", "plan -json", "mcp tools/list") {
		ls := strings.Split(text[f], "\n")
		for i, l := range ls {
			low := strings.ToLower(l)
			skip := false
			for _, a := range docLinesAllowed {
				if strings.Contains(low, a) {
					skip = true
				}
			}
			if needsScope.MatchString(l) && !skip {
				row.Hits = append(row.Hits, fmt.Sprintf("%s:%d: %s", f, i+1, clip(strings.TrimSpace(l), 140)))
			}
			if getsOnly.MatchString(l) && generalClaim.MatchString(l) {
				ctx := strings.Join(ls[max(0, i-1):min(len(ls), i+2)], " ")
				if !strings.Contains(strings.ToUpper(ctx), "HEAD") || strict[f] {
					row.Hits = append(row.Hits, fmt.Sprintf("%s:%d: 'GETs only': %s", f, i+1, clip(strings.TrimSpace(l), 120)))
				}
			}
		}
	}
	addCheck("docs: no public doc says an active option needs -allow or a scope, or that requests are GETs only (without HEAD, or in a plan or an MCP description)", len(row.Hits) == 0,
		"%d lines: %s", len(row.Hits), clipList(row.Hits, 6))

	// The README's benchmark label against the release and the newest record.
	m := latestRun.FindStringSubmatch(text["README.md"])
	if m != nil {
		row.ReadmeDay, row.ReadmeVer = m[1], m[2]
	}
	if b, err := os.ReadFile("CHANGELOG.md"); err == nil {
		if c := changeHead.FindStringSubmatch(string(b)); c != nil {
			row.Changelog = c[1]
		}
	}
	// Release tags only, not the CI's bench-*, hunt-* and trial-*.
	if out, err := exec.Command("git", "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*").Output(); err == nil {
		row.Tag = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	}
	if r, err := newestRecord("bench/history"); err == nil {
		row.Record = strings.SplitN(r.Date, "T", 2)[0]
	}
	ok := row.ReadmeVer != "" && row.ReadmeVer == row.Changelog && semverGE(row.ReadmeVer, row.Tag)
	addCheck("docs: README's 'Latest run (date, vX)' names the newest release (CHANGELOG) and is not older than the tag", ok,
		"README %q on %s, CHANGELOG newest %q, latest tag %q, newest bench record %s", row.ReadmeVer, row.ReadmeDay, row.Changelog, row.Tag, row.Record)
	return row
}

// semverGE: a >= b by major.minor.patch; an empty b is always passed.
func semverGE(a, b string) bool {
	if b == "" {
		return true
	}
	pa, pb := strings.SplitN(a, ".", 3), strings.SplitN(b, ".", 3)
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(strings.SplitN(pb[i], "-", 2)[0])
		if x != y {
			return x > y
		}
	}
	return true
}
