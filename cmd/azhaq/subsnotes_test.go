package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

const teslaTruth = "../../bench/truth/subs/"

func teslaPayload(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(teslaTruth + "tesla-subs-payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCoverageNoteTesla(t *testing.T) {
	p := teslaPayload(t)
	notes := subsNotes([]map[string]any{p}, []tierSet{{countRaw, nil}})
	if len(notes) != 1 {
		t.Fatalf("notes %q", notes)
	}
	t.Log(notes[0])
	want := "coverage (raw candidates): what the independent sources know, not every name that exists. Their pool holds about 1609 names and this run has 1400 of them"
	// The note says what the estimate rests on, counted from the payload.
	dep := subcol.Dependent()
	by, _ := p["found_by"].(map[string]any)
	var f1, f2, observed int
	for _, srcs := range by {
		n := 0
		for _, s := range strs(srcs) {
			if !dep[s] {
				n++
			}
		}
		observed += min(n, 1)
		f1 += map[bool]int{true: 1}[n == 1]
		f2 += map[bool]int{true: 1}[n == 2]
	}
	basis := fmt.Sprintf(". This is an estimate (Chao1) from the %d names the independent sources gave: %d came from one source and %d from two", observed, f1, f2)
	if notes[0] != want+basis {
		t.Errorf("note %q, want %q", notes[0], want+basis)
	}

	// -live: only the printed names count.
	raw, err := os.ReadFile(teslaTruth + "tesla-live-union.txt")
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]bool{}
	for _, n := range strings.Fields(string(raw)) {
		live[n] = true
	}
	notes = subsNotes([]map[string]any{p}, []tierSet{{countDNS, live}})
	t.Log(notes[0])
	if !strings.HasPrefix(notes[0], "coverage (DNS-confirmed): ") || !strings.Contains(notes[0], "holds about 485 names and this run has 481 of them") {
		t.Errorf("live note %q", notes[0])
	}
	if strings.Contains(notes[0], "%") {
		t.Errorf("a lone percentage in %q", notes[0])
	}
	if want := fmt.Sprintf("the other %d of the %d names in this tier came from", len(live)-481, len(live)); len(live) > 481 && !strings.Contains(notes[0], want) {
		t.Errorf("live note %q does not reconcile with the %d names printed", notes[0], len(live))
	}
}

func TestSubsNotesSayWhyWithoutEstimate(t *testing.T) {
	p := map[string]any{"found_by": map[string]any{"a.example.org": []any{"crtsh"}}}
	n := subsNotes([]map[string]any{p}, []tierSet{{countRaw, nil}})
	if want := "coverage (raw candidates): not estimated: 1 independent source(s) gave names (crtsh); an estimate needs two"; len(n) != 1 || n[0] != want {
		t.Errorf("one source: %q, want %q", n, want)
	}
	p["history_error"] = "disk full"
	if n := subsNotes([]map[string]any{p}, []tierSet{{countRaw, nil}}); len(n) != 2 || !strings.Contains(n[0], "disk full") || !strings.HasPrefix(n[1], "coverage (raw candidates): not estimated") {
		t.Errorf("history error: %q", n)
	}
}

// A run whose tiers have no estimate says why, for the one source that
// answered and for none, in the summary's notes (the JSON summary has the same).
func TestSubsSaysWhyItHasNoCoverageEstimate(t *testing.T) {
	t.Chdir(t.TempDir())
	boom := fmt.Errorf("unexpected status code 502 received from https://crt.example/")
	restore := subcol.UseTestSources(
		subcol.TestSource{Name: "crtsh", Default: true, Names: []string{"www.example.org", "app.example.org"}},
		subcol.TestSource{Name: "certspotter", Default: true, Err: boom},
	)
	defer func() { restore() }()
	_, rep, _ := runContract(t, "subs", "-d", "example.org", "-no-history", "-guesses=false")
	notes := strings.Join(rep.Notes, "\n")
	if want := "coverage (raw candidates): not estimated: 1 independent source(s) gave names (crtsh); an estimate needs two; failed: certspotter: " + boom.Error(); !strings.Contains(notes, want) {
		t.Errorf("one source answered: want %q in\n%s", want, notes)
	}
	if strings.Contains(notes, "coverage (raw candidates): what the independent") {
		t.Errorf("an estimate with one source:\n%s", notes)
	}

	restore()
	restore = subcol.UseTestSources(
		subcol.TestSource{Name: "crtsh", Default: true, Err: boom},
		subcol.TestSource{Name: "certspotter", Default: true, Err: boom},
	)
	_, rep, _ = runContract(t, "subs", "-d", "example.org", "-no-history", "-guesses=false")
	notes = strings.Join(rep.Notes, "\n")
	if want := "coverage (raw candidates): not estimated: 0 independent source(s) gave names (none); an estimate needs two; failed: certspotter: " + boom.Error() + "; crtsh: " + boom.Error(); !strings.Contains(notes, want) {
		t.Errorf("no source answered: want %q in\n%s", want, notes)
	}
}

func TestSlowSourceNamesTheOneThatSetTheTime(t *testing.T) {
	srcs := map[string]any{
		"crtsh":           map[string]any{"seconds": 4.2},
		"subdomaincenter": map[string]any{"seconds": 31.0},
		"history":         map[string]any{"seconds": 0.0},
		"chaos":           map[string]any{"skipped": "no key"},
	}
	n := slowSource("vulnweb.com", srcs)
	if !strings.Contains(n, "subdomaincenter took 31 s, the next slowest source 4 s") {
		t.Errorf("note %q", n)
	}
	srcs["crtsh"] = map[string]any{"seconds": 20.0}
	if n := slowSource("vulnweb.com", srcs); n != "" {
		t.Errorf("two sources near each other: %q", n)
	}
}

func TestGuessCheckSaysWhereTheTimeWent(t *testing.T) {
	srcs := map[string]any{
		"subdomaincenter": map[string]any{"seconds": 10.6, "kept": 16.0, "dropped_unresolved": 1575.0, "checked_seconds": 452.0},
		"crtsh":           map[string]any{"seconds": 14.5},
	}
	n := guessCheck("hackerone.com", srcs)
	if !strings.Contains(n, "the 1591 names only subdomaincenter held were looked up in DNS in 452 s: 16 resolved, 1575 did not exist") || !strings.Contains(n, "-live -guesses=false leaves the guesses unlooked") {
		t.Errorf("note %q", n)
	}
	// A quick check is said too, without the advice on its cost.
	srcs["subdomaincenter"].(map[string]any)["checked_seconds"] = 3.0
	n = guessCheck("hackerone.com", srcs)
	if !strings.Contains(n, "in 3 s: 16 resolved, 1575 did not exist") || strings.Contains(n, "-dns-rate") {
		t.Errorf("a quick check: %q", n)
	}
	// The history's row shares the pool: the names are not counted twice.
	srcs["history"] = map[string]any{"kept": 16.0, "dropped_unresolved": 1575.0, "checked_seconds": 3.0}
	if n := guessCheck("hackerone.com", srcs); !strings.Contains(n, "the 1591 names only history, subdomaincenter held") {
		t.Errorf("two rows of one pool: %q", n)
	}
}

func TestSamplingNoteSaysWhatABoundLeftUntaken(t *testing.T) {
	srcs := map[string]any{
		"subdomaincenter": map[string]any{
			"rounds":           []any{map[string]any{"names": 500.0}},
			"sample_ceiling":   12.0,
			"sampling_stopped": "another sample would not fit the 20 s budget for further samples",
			"sampling_bounded": true,
		},
		"crtsh": map[string]any{"seconds": 2.0},
	}
	n := samplingNote("vulnweb.com", srcs)
	if !strings.Contains(n, "subdomaincenter was asked for 1 sample of its guesses (the first is what subfinder | dnsx checks) and not again: another sample would not fit the 20 s budget") || !strings.Contains(n, "up to 11 more samples left untaken") || !strings.Contains(n, "-guess-samples N") {
		t.Errorf("note %q", n)
	}
	delete(srcs["subdomaincenter"].(map[string]any), "sampling_bounded")
	if n := samplingNote("vulnweb.com", srcs); n != "" {
		t.Errorf("a stop that was a finding: %q", n)
	}
}

// With several domains and no estimate for any, each has its own line.
func TestSubsNotesSayWhyForEachDomainWithoutEstimate(t *testing.T) {
	a := map[string]any{"domain": "a.example", "found_by": map[string]any{"www.a.example": []any{"crtsh"}}}
	b := map[string]any{"domain": "b.example", "found_by": map[string]any{}}
	n := subsNotes([]map[string]any{a, b}, []tierSet{{countRaw, nil}})
	if len(n) != 2 || !strings.HasPrefix(n[0], "coverage (raw candidates, a.example): not estimated: 1 independent") || !strings.HasPrefix(n[1], "coverage (raw candidates, b.example): not estimated: 0 independent") {
		t.Errorf("notes %q", n)
	}
}
