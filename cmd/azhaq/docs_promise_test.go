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
		"../../docs/commands/crawl.md":    "an endpoint that resets data or logs out is asked like any other",
		"../../docs/TROUBLESHOOTING.md":   "a GET that deletes or logs out is asked",
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
