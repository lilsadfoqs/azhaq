package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The promise about GET is stated once, in CONCEPTS, and the pages that talk
// of what azhaq sends carry it: a write is a method, a GET can change data and
// is asked, and only -deny-path keeps a URL out.
func TestDocsStateWhatTheGETPromiseIs(t *testing.T) {
	concepts := readDoc(t, "../../docs/CONCEPTS.md")
	for _, want := range []string{
		"Without a flag, every request azhaq sends to a target on purpose is a GET",
		`"A write" in these pages means a request with a method other than GET, HEAD or OPTIONS`,
		"A GET can change data or end a session, and azhaq requests it",
		"`-deny-path REGEX` keeps a path out of every request",
	} {
		if !strings.Contains(concepts, want) {
			t.Errorf("docs/CONCEPTS.md lacks %q", want)
		}
	}
	for file, want := range map[string]string{
		"../../README.md":                 "A GET can change data or end a session",
		"../../docs/commands/run.md":      "A GET can change data or end a session",
		"../../docs/commands/crawl.md":    "An endpoint that resets data under another name is asked like any other",
		"../../docs/TROUBLESHOOTING.md":   "a GET that deletes or logs out under another name is asked",
		"../../docs/MIGRATING.md":         "a GET operation named in an API description is requested too",
		"../../docs/MCP.md":               "asks every GET it finds in scope",
		"../../docs/commands/plan.md":     "It does not list the URLs a crawl will find",
		"../../docs/CONCEPTS.md":          "not the URLs a crawl will find",
		"../../.github/ci/trial/GATE.md":  "no write method (anything but GET, HEAD or OPTIONS) sent without its flag",
		"../../.github/ci/trial/BRIEF.md": "no write method (anything but GET, HEAD or OPTIONS) sent without its flag",
		"../../.github/ci/hunt/BRIEF.md":  "no write method (anything but GET, HEAD or OPTIONS) sent without its flag",
	} {
		if !strings.Contains(readDoc(t, file), want) {
			t.Errorf("%s lacks %q", file, want)
		}
	}
}

// Every page that counts the built-in path checks gives the number a plan
// lists.
func TestDocsCountTheBuiltInPathsAsThePlanDoes(t *testing.T) {
	n := len(planJSON(t, "-url", "http://127.0.0.1:3001/").Paths)
	count := regexp.MustCompile(`(\d+) built-in path`)
	for _, file := range []string{"../../README.md", "../../docs/CONCEPTS.md", "../../docs/commands/run.md", "../../docs/commands/plan.md", "../../docs/commands/crawl.md", "../../docs/MIGRATING.md", "../../docs/ARCHITECTURE.md"} {
		for _, m := range count.FindAllStringSubmatch(readDoc(t, file), -1) {
			if got, _ := strconv.Atoi(m[1]); got != n {
				t.Errorf("%s says %s built-in path checks, a plan lists %d", file, m[1], n)
			}
		}
	}
}

// The README says how a cell of the roles table reads.
func TestRolesTableCellsReadAsTheREADMESays(t *testing.T) {
	for want, a := range map[string]answer{
		"-":           {},
		"401":         {Status: 401},
		"200:79":      {Status: 200, Hash: "h", Length: 79},
		"200:1.1k":    {Status: 200, Hash: "h", Length: 1126},
		"200:2.0M":    {Status: 200, Hash: "h", Length: 2 << 20},
		"200:err":     {Status: 200, Hash: "h", Length: 79, Error: true},
		"200:refused": {Status: 200, Hash: "h", Length: 79, Refusal: true},
		"200:79?":     {Status: 200, Hash: "h", Length: 79, SessionSuspect: true},
	} {
		if got := answerCell(a); got != want {
			t.Errorf("answerCell(%+v) = %q, want %q", a, got, want)
		}
	}
	readme := readDoc(t, "../../README.md")
	for _, want := range []string{"as `status:size`", "`200:refused`", "A `-` is a role that was never asked"} {
		if !strings.Contains(readme, want) {
			t.Errorf("the README's roles example does not say %q", want)
		}
	}
}
