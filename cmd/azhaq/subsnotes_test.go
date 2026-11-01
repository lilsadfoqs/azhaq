package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
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
	notes := subsNotes([]map[string]any{p}, nil)
	if len(notes) != 1 {
		t.Fatalf("notes %q", notes)
	}
	t.Log(notes[0])
	want := "coverage: what the independent sources know, not every name that exists. Their pool holds about 1609 names and this run has 1400 of them"
	if notes[0] != want {
		t.Errorf("note %q", notes[0])
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
	notes = subsNotes([]map[string]any{p}, live)
	t.Log(notes[0])
	if !strings.Contains(notes[0], "holds about 485 names and this run has 481 of them") {
		t.Errorf("live note %q", notes[0])
	}
	if strings.Contains(notes[0], "%") {
		t.Errorf("a lone percentage in %q", notes[0])
	}
	if want := fmt.Sprintf("the other %d of the %d names printed came from", len(live)-481, len(live)); len(live) > 481 && !strings.Contains(notes[0], want) {
		t.Errorf("live note %q does not reconcile with the %d names printed", notes[0], len(live))
	}
}

func TestSubsNotesQuietWithoutEstimate(t *testing.T) {
	p := map[string]any{"found_by": map[string]any{"a.example.org": []any{"crtsh"}}}
	if n := subsNotes([]map[string]any{p}, nil); len(n) != 0 {
		t.Errorf("one source: %q", n)
	}
	p["history_error"] = "disk full"
	if n := subsNotes([]map[string]any{p}, nil); len(n) != 1 || !strings.Contains(n[0], "disk full") {
		t.Errorf("history error: %q", n)
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
	if !strings.Contains(n, "checking the 1591 names subdomaincenter guessed in DNS took 452 s") {
		t.Errorf("note %q", n)
	}
	srcs["subdomaincenter"].(map[string]any)["checked_seconds"] = 3.0
	if n := guessCheck("hackerone.com", srcs); n != "" {
		t.Errorf("a quick check: %q", n)
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
