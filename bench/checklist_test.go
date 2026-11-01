package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every capability of GATE.md's checklist is either checked by a unit or
// listed as not covered with its reason, and every unit named exists.
func TestChecklistCoversGateMd(t *testing.T) {
	raw, err := os.ReadFile("../.github/ci/trial/GATE.md")
	if err != nil {
		t.Fatal(err)
	}
	caps := gateCapabilities(string(raw))
	if len(caps) < 25 {
		t.Fatalf("read %d capabilities from GATE.md: %v", len(caps), caps)
	}
	for _, c := range caps {
		if checklistCover[c] == "" {
			t.Errorf("GATE.md's checklist has %q, which checklistCover does not mention", c)
		}
	}
	for c := range checklistCover {
		if !slices.Contains(caps, c) {
			t.Errorf("checklistCover has %q, which GATE.md's checklist does not", c)
		}
	}
	known := canonicalUnits()
	for _, u := range checklistUnits {
		if !slices.Contains(known, u) {
			t.Errorf("-checklist names the unit %q, which does not exist", u)
		}
	}
}

// The checklist's own unit passes on azhaq as it is: every check holds against
// the stand-in site (the labs' part is the CI job's).
func TestChecklistPassesOnTheStandIns(t *testing.T) {
	if testing.Short() {
		t.Skip("runs azhaq against a stand-in site for a minute")
	}
	skipWithoutPython(t)
	oldRec, oldAz, oldWork := rec, azhaq, work
	rec, azhaq, work = record{}, smokeBin, t.TempDir()
	t.Cleanup(func() { rec, azhaq, work = oldRec, oldAz, oldWork })
	benchChecklist()
	if len(rec.Checks) < 18 {
		t.Errorf("only %d checks ran", len(rec.Checks))
	}
	for _, c := range rec.Checks {
		if !c.Pass {
			t.Errorf("%s: %s", c.Name, c.Detail)
		}
	}
	for _, c := range rec.Checks {
		if !strings.HasPrefix(c.Name, "checklist: ") {
			t.Errorf("a check outside the checklist's namespace: %s", c.Name)
		}
	}
}

// A tool that deletes something, asks a denied path and invents its counts
// fails the checks that exist to catch exactly that.
func TestChecklistFailsOnAToolThatBreaksTheClaims(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	fake := filepath.Join(t.TempDir(), "azhaq")
	script := `#!/bin/sh
for a; do case "$a" in http://*) u="$a";; esac; done
curl -s -X DELETE "${u}admin/purge" -o /dev/null
curl -s "${u}logout" -o /dev/null
echo '{"type":"summary","requests":2}' >&2
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldRec, oldAz := rec, azhaq
	rec, azhaq = record{}, fake
	t.Cleanup(func() { rec, azhaq = oldRec, oldAz })
	site, err := newCLSite()
	if err != nil {
		t.Fatal(err)
	}
	defer site.close()
	c := &checklist{dir: t.TempDir(), site: site}
	c.mapAndCounts()
	c.denyPath()
	failed := map[string]bool{}
	for _, ck := range rec.Checks {
		failed[ck.Name] = !ck.Pass
	}
	for _, name := range []string{
		"checklist: run: summary = ledger = what the site saw, exit 0",
		"checklist: a plain map sends reads only, though the page, its script and its API description name writes and a GraphQL endpoint",
		"checklist: -deny-path keeps /logout and /admin out of every request and the summary says so",
	} {
		if !failed[name] {
			t.Errorf("%q passed for a tool that breaks it (checks: %v)", name, failed)
		}
	}
}
