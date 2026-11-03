package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The recorded tesla.com run (truth/subs): azhaq's names and, from the
// same domain, the names a resolver confirmed. A -live run prints only the
// confirmed ones, each as tier dns, and counts the rest as raw candidates.
func TestTiersOnRecordedTeslaRun(t *testing.T) {
	raw, err := os.ReadFile("truth/subs/tesla-subs-payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	liveRaw, err := os.ReadFile("truth/subs/tesla-live-union.txt")
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]bool{}
	for _, n := range strings.Fields(string(liveRaw)) {
		live[n] = true
	}
	var rows []tierRow
	ref := map[string]bool{}
	for _, n := range p.Names {
		if live[n] {
			rows = append(rows, tierRow{n, "dns"})
			ref[n] = true
		}
	}
	counts := map[string]int{"raw candidates": len(p.Names), "DNS-confirmed": len(rows)}
	if len(rows) == 0 || len(rows) == len(p.Names) {
		t.Fatalf("the recorded run has %d confirmed of %d names", len(rows), len(p.Names))
	}
	if got := tierProblems(rows, counts, ref); len(got) != 0 {
		t.Fatalf("a correct run has problems: %q", got)
	}
	// A candidate printed in a -live run is a problem.
	bad := append(append([]tierRow(nil), rows...), tierRow{"junk.tesla.com", "candidate"})
	counts["DNS-confirmed"] = len(bad)
	if got := tierProblems(bad, counts, ref); len(got) == 0 {
		t.Error("a candidate row in a -live run was accepted")
	}
	// Raw candidates counted as confirmed: the counts say all of them are.
	counts["DNS-confirmed"] = len(p.Names)
	if got := tierProblems(rows, counts, ref); len(got) == 0 {
		t.Error("raw candidates counted as DNS-confirmed were accepted")
	}
	// A name the reference's lookups confirmed and the run did not.
	counts["DNS-confirmed"] = len(rows)
	ref["only-the-reference.tesla.com"] = true
	if got := tierProblems(rows, counts, ref); len(got) == 0 {
		t.Error("a confirmed name missing from the run was accepted")
	}
}
