package portcol

import (
	"encoding/json"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func stored(p map[string]any) types.StoredObservation {
	raw, _ := json.Marshal(p)
	return types.StoredObservation{Observation: types.Observation{Collector: Name, Kind: "ports", Payload: raw}}
}

// What a limit left unasked is counted from the rows it stopped: the ports of
// the part-asked addresses, and every port of the addresses of the block it
// never reached. An address the block lists as finished has none left, however
// stale its last checkpoint; a scan that ended after leaves none.
func TestNotAskedCountsWhatTheStoppedRowsLeft(t *testing.T) {
	obs := []types.StoredObservation{
		// 10.0.0.1 and .2 part-asked (pass 1: 40 and 10 ports left), .3 finished (place 4) but its checkpoint is old.
		stored(map[string]any{"ip": "10.0.0.1", "partial": true, "prefix": "10.0.0.0/24", "pass": 1, "ports_left": 40}),
		stored(map[string]any{"ip": "10.0.0.2", "partial": true, "prefix": "10.0.0.0/24", "pass": 1, "ports_left": 99}),
		stored(map[string]any{"ip": "10.0.0.2", "partial": true, "prefix": "10.0.0.0/24", "pass": 1, "ports_left": 10}),
		stored(map[string]any{"ip": "10.0.0.3", "partial": true, "prefix": "10.0.0.0/24", "pass": 1, "ports_left": 70}),
		// A whole scan came after this one.
		stored(map[string]any{"ip": "10.0.0.9", "partial": true, "prefix": "10.0.0.0/24", "pass": 1, "ports_left": 5}),
		stored(map[string]any{"ip": "10.0.0.9", "prefix": "10.0.0.0/24"}),
		// 6 of 256 addresses reached, 3 finished (places 4, 10, 11 and 12 here: 4 listed).
		stored(map[string]any{"range": true, "stopped": true, "prefix": "10.0.0.0/24", "addresses": 6, "addresses_of": 256, "swept": "4,10-12", "pass": 1}),
		// A block that ended whole is not left.
		stored(map[string]any{"range": true, "stopped": true, "prefix": "10.1.0.0/24", "addresses": 1, "addresses_of": 256, "swept": "1", "pass": 1}),
		stored(map[string]any{"range": true, "prefix": "10.1.0.0/24", "addresses": 256}),
	}
	addrs, ports := NotAsked(obs, 100)
	if wantA, wantP := 2+250, 40+10+250*100; addrs != wantA || ports != wantP {
		t.Errorf("%d addresses, %d ports; want %d, %d", addrs, ports, wantA, wantP)
	}
	// A scan with no second pass has no ports_left: the ports asked are in the row.
	addrs, ports = NotAsked([]types.StoredObservation{stored(map[string]any{"ip": "10.0.0.1", "partial": true, "asked_ports": "1-3,8080"})}, 10)
	if addrs != 1 || ports != 6 {
		t.Errorf("a row with asked_ports: %d addresses, %d ports; want 1, 6", addrs, ports)
	}
}
