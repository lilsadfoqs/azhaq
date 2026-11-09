package main

import (
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// subs -live takes the time of its slowest source and no more, as
// subfinder | dnsx does: the guess check, the wildcard probe and the end of the
// run add the DNS of the names at -dns-rate and a margin, not a wait of their own.
func TestSubsLiveTakesNoLongerThanItsSlowestSource(t *testing.T) {
	t.Chdir(t.TempDir())
	real, guesses, a := vulnwebShaped()
	z := &countingZone{a: a, byType: map[string]int{}, byName: map[string]int{}}
	resolvers := serveCounting(t, z, 1)
	const slowest = 1500 * time.Millisecond
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "slow", Default: true, Names: real, Delay: slowest},
		subcol.TestSource{Name: "fast", Default: true, Names: real[:50]},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Names: guesses},
	)()
	t0 := time.Now()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-dns-rate", "1000", "-no-history")
	took := time.Since(t0)
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	if limit := slowest*105/100 + 500*time.Millisecond; took > limit {
		t.Errorf("the run took %s, its slowest source %s: the bar is the source's time and the DNS of the names, %s", took, slowest, limit)
	}
}
