package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
)

var permuteSeeds = []string{"api.example.org", "dev.example.org", "staging.example.org"}

// subs -w with three words finds three seeds, and -permute varies each. The
// stub resolver knows the three names only.
func permuteSubsArgs(t *testing.T, resolver string, extra ...string) []string {
	t.Helper()
	words := writeList(t, "api", "dev", "staging")
	return append([]string{"subs", "-d", "example.org", "-sources", "none", "-w", words, "-permute", "-live",
		"-resolvers", resolver, "-no-history", "-db", "p.db"}, extra...)
}

// plan counts the names three seeds make as the generator asks them: a
// name two seeds make alike once, and the stub resolver is asked each of them.
func TestPlanCountsThePermutationNamesTheGeneratorAsks(t *testing.T) {
	t.Chdir(t.TempDir())
	want := brutecol.PermuteNames(permuteSeeds)
	if sum := 3 * brutecol.PermuteCount(permuteSeeds[0]); len(want) >= sum {
		t.Fatalf("%d names for 3 seeds, %d for three alone: the shared words are asked once", len(want), sum)
	}
	z := &countingZone{
		a:      map[string]string{"api.example.org": "192.0.2.1", "dev.example.org": "192.0.2.2", "staging.example.org": "192.0.2.3"},
		byType: map[string]int{}, byName: map[string]int{},
	}
	resolver := serveCounting(t, z, 1)
	list := writeList(t, permuteSeeds...)
	plan := planJSON(t, "-list", list, "-sources", "none", "-permute", "-allow", "example.org", "-resolvers", resolver, "-dns-rate", "10")
	pc := plan.Estimate.Permute
	if pc == nil || pc.Names != 3 || pc.Variations != len(want) || pc.PerName != brutecol.PermuteCount("name.example.org") {
		t.Fatalf("plan's permute estimate %+v, the generator makes %d names for 3 seeds", pc, len(want))
	}
	if pc.Seconds == nil || *pc.Seconds != float64((len(want)+9)/10) || pc.Resolvers != 1 {
		t.Errorf("the time at -dns-rate 10 on one resolver: %+v, want %d s", pc, (len(want)+9)/10)
	}
	var est int64 = -1
	for _, st := range plan.Estimate.Stages {
		for _, c := range st.Collectors {
			if c.Collector == "azhaq-permute" && c.Estimate != nil {
				est = c.Estimate.DNS
			}
		}
	}
	if est != int64(len(want)) {
		t.Errorf("the stage counts %d DNS queries for -permute, the generator asks %d names", est, len(want))
	}

	// The run asks exactly those names.
	_, rep, code := runContract(t, permuteSubsArgs(t, resolver)...)
	if code != exitOK {
		t.Fatalf("exit %d %q", code, rep.Stopped)
	}
	z.mu.Lock()
	missing := 0
	for _, n := range want {
		if z.byName[n] == 0 {
			missing++
		}
	}
	z.mu.Unlock()
	if missing > 0 {
		t.Errorf("%d of the %d names plan counts were never asked", missing, len(want))
	}
	var note string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "-permute: ") {
			note = n
		}
	}
	if !strings.Contains(note, fmt.Sprintf("3 names varied, %d variation names to ask", len(want))) || !strings.Contains(note, fmt.Sprintf("%d asked", len(want))) {
		t.Errorf("the summary does not state the job and what was asked (%d names): %q", len(want), rep.Notes)
	}
}

// A run cut by -max-time says how many permutation names it left.
func TestSubsCutByMaxTimeNamesThePermutationsLeft(t *testing.T) {
	t.Chdir(t.TempDir())
	resolver, _ := slowResolver(t, 100*time.Millisecond, permuteSeeds...)
	_, rep, code := runContract(t, permuteSubsArgs(t, resolver, "-dns-rate", "20", "-max-time", "4s")...)
	if code != exitLimit || !strings.Contains(rep.Stopped, "-max-time") {
		t.Fatalf("exit %d, stopped %q", code, rep.Stopped)
	}
	var note string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "-permute: ") {
			note = n
		}
	}
	all := len(brutecol.PermuteNames(permuteSeeds))
	if !strings.Contains(note, fmt.Sprintf("%d variation names to ask", all)) || !strings.Contains(note, "not asked when the run stopped (azhaq resume asks them)") {
		t.Errorf("the summary of a cut run does not say what is left of the %d names: %q", all, rep.Notes)
	}
	if !strings.Contains(note, "at -dns-rate 20 on 1 resolver") {
		t.Errorf("no time at the rate: %q", note)
	}
}

// The progress line counts the permutation names asked against all of them.
func TestProgressLineCountsThePermutationNames(t *testing.T) {
	line := progressCfg{}.line(progressSnap{Left: -1}, progressSnap{At: 10 * time.Second, Left: 4, PermAsked: 75, PermTotal: 2433})
	if !strings.Contains(line, "75 of 2433 permutation names asked") {
		t.Errorf("the progress line: %s", line)
	}
	if strings.Contains(progressCfg{}.line(progressSnap{Left: -1}, progressSnap{At: 10 * time.Second, Left: 4}), "permutation") {
		t.Errorf("a run with no permutation work names them")
	}
}

// While -permute works, a run's progress lines count the names asked
// against all the names the seeds make.
func TestRunProgressCountsThePermutationNamesAskedOfAll(t *testing.T) {
	defer func(d time.Duration) { stderrProgressEvery = d }(stderrProgressEvery)
	stderrProgressEvery = 300 * time.Millisecond
	t.Chdir(t.TempDir())
	resolver, _ := slowResolver(t, 20*time.Millisecond, permuteSeeds...)
	words := writeList(t, "api", "dev", "staging")
	all := len(brutecol.PermuteNames(permuteSeeds))
	_, errOut, _ := captureBoth(t, func() error {
		return run([]string{"run", "-domain", "example.org", "-sources", "none", "-dns-brute", words, "-permute", "-resolvers", resolver,
			"-dns-rate", "40", "-max-time", "3s", "-no-paths", "-depth", "1", "-no-history", "-ledger", "off", "-db", "pr.db"})
	})
	want := fmt.Sprintf(" of %d permutation names asked", all)
	for _, l := range lines(errOut) {
		if strings.HasPrefix(l, "azhaq: ") && strings.Contains(l, want) {
			return
		}
	}
	t.Errorf("no progress line says %q:\n%s", want, errOut)
}
