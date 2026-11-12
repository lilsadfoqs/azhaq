package main

import (
	"encoding/json"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func storedPortRow(p map[string]any) types.StoredObservation {
	raw, _ := json.Marshal(p)
	return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}}
}

// A stopped block has a row for every run that touched it: the addresses are
// counted once, by the largest row, and never above the size of the block.
func TestPortAddressesCountsAStoppedBlockOnce(t *testing.T) {
	var obs []types.StoredObservation
	for _, n := range []int{75, 150, 225, 256, 256} {
		obs = append(obs, storedPortRow(map[string]any{"range": true, "prefix": "10.1.0.0/24", "addresses": n, "with_open": n / 40, "stopped": true}))
	}
	obs = append(obs, storedPortRow(map[string]any{"range": true, "prefix": "10.1.0.0/24", "addresses": 300, "with_open": 400}))
	// A block inside the range is the range's, and a second block counts apart.
	obs = append(obs, storedPortRow(map[string]any{"range": true, "prefix": "10.1.0.0/28", "addresses": 16, "with_open": 1}))
	obs = append(obs, storedPortRow(map[string]any{"range": true, "prefix": "10.2.0.0/30", "addresses": 4, "with_open": 1}))
	scanned, open := portAddresses(obs)
	if scanned != 256+4 {
		t.Errorf("scanned %d, want 260 (a /24 once, a /30)", scanned)
	}
	if open != 256+1 {
		t.Errorf("open %d, want 257 (never above the block's size)", open)
	}
}
