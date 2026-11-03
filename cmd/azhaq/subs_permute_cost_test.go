package main

import (
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/brutecol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/types"
)

// subs -permute asks variations of names no one knows before the sources
// answer: the estimate says it leaves them out, as it does for the sources'
// own names, instead of showing a total that reads as complete.
func TestSubsPermuteEstimateNamesWhatItLeavesOut(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.10"}})
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "api.example.org"}})()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-permute", "-resolvers", resolvers, "-no-history")
	if code != exitOK || rep.Cost == nil || rep.Cost.Estimate == nil {
		t.Fatalf("exit %d cost %+v", code, rep.Cost)
	}
	if !rep.Cost.AtLeast {
		t.Errorf("the estimate is not marked as a floor")
	}
	var named bool
	for _, st := range rep.Cost.Stages {
		named = named || st.Stage == "names" && st.AtLeast && strings.Contains(st.NotCounted, "-permute")
	}
	if !named {
		t.Errorf("no stage names the permutation queries as not counted: %+v", rep.Cost.Stages)
	}
	if rep.Cost.Actual.DNS < 100 {
		t.Fatalf("the run sent %d DNS queries: the test needs the permutation ones", rep.Cost.Actual.DNS)
	}
}

// A name given as a target is varied for certain: its variations are counted.
func TestEstimateCountsTheVariationsOfANameGiven(t *testing.T) {
	seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "api.example.org"}}
	want := int64(brutecol.PermuteCount("api.example.org"))
	if want < 100 {
		t.Fatalf("PermuteCount %d", want)
	}
	est := estimateCost([]types.Seed{seed}, [][]string{{"azhaq-permute"}}, func(string) bool { return false },
		map[string]bool{"permute": true}, costEnv{}, func(string, types.Seed) int { return 0 })
	if est.Total.DNS != want {
		t.Errorf("estimated %d DNS queries, the variations are %d", est.Total.DNS, want)
	}
	if !est.AtLeast {
		t.Errorf("names the sources find later bring more: the estimate is a floor")
	}
}
