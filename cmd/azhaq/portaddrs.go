package main

import (
	"net/netip"

	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/types"
)

// portAddresses counts, from the rows of a port scan, the distinct addresses
// it asked and the distinct addresses it found a port open on. A range's row
// says how many of its addresses were asked and how many had an open port; an
// address given on its own has a row of its own. An address that is in a range
// and also given on its own (a name that resolves into it, a line of a list)
// is one address: counted by its range, not again.
func portAddresses(obs []types.StoredObservation) (scanned, open int) {
	type block struct {
		pf       netip.Prefix
		withOpen int
	}
	var blocks []block
	var singles []netip.Addr        // addresses given on their own, once each
	openAt := map[netip.Addr]bool{} // the addresses with an open port, in a range or not
	seen := map[netip.Addr]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-ports" || o.Kind != "ports" {
			continue
		}
		p := payloadOf(o.Observation)
		if p[portcol.CheckpointKey] == true || p["unresolved"] != nil {
			continue
		}
		if p["range"] == true {
			scanned += intOf(p["addresses"])
			pf, err := netip.ParsePrefix(pstr(p["prefix"]))
			if err != nil {
				open += intOf(p["with_open"]) // no prefix to place the rows by
				continue
			}
			blocks = append(blocks, block{pf.Masked(), intOf(p["with_open"])})
			continue
		}
		ip, err := netip.ParseAddr(pstr(p["ip"]))
		if err != nil {
			continue
		}
		isOpen := false
		if sv, _ := p["services"].([]any); len(sv) > 0 {
			isOpen = true
		} else if uo, _ := p["udp_open"].([]any); len(uo) > 0 {
			isOpen = true
		}
		if isOpen {
			openAt[ip] = true
		}
		if p["prefix"] == nil && !seen[ip] { // one address under two names
			seen[ip] = true
			singles = append(singles, ip)
		}
	}
	inBlock := func(ip netip.Addr) int {
		for i, b := range blocks {
			if b.pf.Contains(ip) {
				return i
			}
		}
		return -1
	}
	// A range's own count of the addresses with a port open, or the rows found
	// inside it when they are more.
	rowsIn := make([]int, len(blocks))
	for ip := range openAt {
		if i := inBlock(ip); i >= 0 {
			rowsIn[i]++
		}
	}
	for i, b := range blocks {
		open += max(b.withOpen, rowsIn[i])
	}
	for _, ip := range singles {
		if inBlock(ip) >= 0 {
			continue
		}
		scanned++
		if openAt[ip] {
			open++
		}
	}
	return scanned, open
}

func pstr(v any) string { s, _ := v.(string); return s }
