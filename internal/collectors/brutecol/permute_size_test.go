package brutecol

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/types"
)

// PermuteNames is what Permute asks for the seeds: the count the plan and the
// summary state is the one the generator makes, each name once.
func TestPermuteNamesAreWhatPermuteAsks(t *testing.T) {
	hosts := []string{"api.example.org", "dev.example.org", "staging.example.org"}
	var seeds []types.Seed
	for _, h := range hosts {
		seeds = append(seeds, types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": h}})
	}
	want := PermuteNames(PermuteHosts(seeds))
	if len(want) == 0 || len(want) >= 3*PermuteCount(hosts[0]) {
		t.Fatalf("%d names for three seeds, %d for each alone", len(want), PermuteCount(hosts[0]))
	}
	ResetPermuteProgress()
	p := pool(t)
	perm := &Permute{Pool: p, Wild: dnsr.NewWildcards(p)}
	var mu sync.Mutex
	tried := 0
	for _, s := range seeds {
		if _, err := perm.Run(context.Background(), s, func(o types.Observation) error {
			var pl struct{ Tried int }
			_ = json.Unmarshal(o.Payload, &pl)
			mu.Lock()
			tried += pl.Tried
			mu.Unlock()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if tried != len(want) {
		t.Errorf("Permute asked %d names, PermuteNames counts %d", tried, len(want))
	}
	if asked, total := PermuteProgress(nil); asked != len(want) || total != asked {
		t.Errorf("progress %d of %d, want %d of %d", asked, total, len(want), len(want))
	}
	// A name of a task not run is left until it is asked.
	if left := PermuteLeft([]string{"other.example.org"}); left == 0 {
		t.Errorf("no names left for a name not varied")
	}
}
