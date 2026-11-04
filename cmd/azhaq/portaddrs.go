package main

import (
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/types"
)

// portAddresses counts, from the rows of a port scan, the addresses it asked
// and the addresses it found a port open on. A range's row says how many of
// its addresses were asked and how many had an open port; an address given
// on its own has a row of its own. The per-address rows of a range are not
// counted again.
func portAddresses(obs []types.StoredObservation) (scanned, open int) {
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-ports" || o.Kind != "ports" {
			continue
		}
		p := payloadOf(o.Observation)
		switch {
		case p[portcol.CheckpointKey] == true || p["unresolved"] != nil:
		case p["range"] == true:
			scanned += intOf(p["addresses"])
			open += intOf(p["with_open"])
		case p["prefix"] == nil:
			ip, _ := p["ip"].(string)
			if seen[ip] {
				continue // one address under two names
			}
			seen[ip] = true
			scanned++
			if sv, _ := p["services"].([]any); len(sv) > 0 {
				open++
			} else if uo, _ := p["udp_open"].([]any); len(uo) > 0 {
				open++
			}
		}
	}
	return scanned, open
}
