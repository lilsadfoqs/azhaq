package main

import (
	"net/netip"
	"slices"

	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/types"
)

// portAddresses counts, from the rows of a port scan, the distinct addresses
// it asked and the distinct addresses it found a port open on. A range's row
// says how many of its addresses were asked and how many had an open port; an
// address given on its own has a row of its own. A range a limit stopped has a
// row for each run that touched it, each counting what the block had finished
// so far: the block counts once, by its largest row, and never above its size.
// An address that is in a range
// and also given on its own (a name that resolves into it, a line of a list)
// is one address: counted by its range, not again.
func portAddresses(obs []types.StoredObservation) (scanned, open int) {
	type block struct {
		pf       netip.Prefix
		asked    int
		withOpen int
	}
	var blocks []block
	at := map[netip.Prefix]int{}    // the place of a prefix in blocks
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
			pf, err := netip.ParsePrefix(pstr(p["prefix"]))
			if err != nil {
				scanned += intOf(p["addresses"])
				open += intOf(p["with_open"]) // no prefix to place the rows by
				continue
			}
			pf = pf.Masked()
			i, ok := at[pf]
			if !ok {
				i = len(blocks)
				at[pf] = i
				blocks = append(blocks, block{pf: pf})
			}
			blocks[i].asked = max(blocks[i].asked, intOf(p["addresses"]))
			blocks[i].withOpen = max(blocks[i].withOpen, intOf(p["with_open"]))
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
	// A block inside another is counted by the larger one.
	all := slices.Clone(blocks)
	blocks = slices.DeleteFunc(blocks, func(b block) bool {
		return slices.ContainsFunc(all, func(o block) bool {
			return o.pf.Bits() < b.pf.Bits() && o.pf.Contains(b.pf.Addr())
		})
	})
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
		size := blockSize(b.pf)
		scanned += min(b.asked, size)
		open += min(max(b.withOpen, rowsIn[i]), size)
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

// blockSize is how many addresses a prefix holds, capped where an int cannot.
func blockSize(pf netip.Prefix) int {
	bits := pf.Addr().BitLen() - pf.Bits()
	if bits > 30 {
		return 1 << 30
	}
	return 1 << bits
}

func pstr(v any) string { s, _ := v.(string); return s }

// quietAddrs lists the addresses a scan asked that showed no open port, up to
// max: those a second pass skipped. nil when there are more, or a range row has
// no prefix to list them by.
func quietAddrs(obs []types.StoredObservation, max int) []string {
	var prefixes []netip.Prefix
	asked, openAt := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-ports" || o.Kind != "ports" {
			continue
		}
		p := payloadOf(o.Observation)
		if p[portcol.CheckpointKey] == true || p["unresolved"] != nil {
			continue
		}
		if p["range"] == true {
			pf, err := netip.ParsePrefix(pstr(p["prefix"]))
			if err != nil {
				return nil
			}
			prefixes = append(prefixes, pf.Masked())
			continue
		}
		ip, err := netip.ParseAddr(pstr(p["ip"]))
		if err != nil {
			continue
		}
		asked[ip] = true
		sv, _ := p["services"].([]any)
		uo, _ := p["udp_open"].([]any)
		if len(sv) > 0 || len(uo) > 0 {
			openAt[ip] = true
		}
	}
	for _, pf := range prefixes {
		if pf.Addr().Is6() && pf.Bits() < 120 || pf.Addr().Is4() && pf.Bits() < 22 {
			return nil
		}
		for a := pf.Addr(); a.IsValid() && pf.Contains(a); a = a.Next() {
			asked[a] = true
		}
	}
	var out []string
	for a := range asked {
		if !openAt[a] {
			out = append(out, a.String())
			if len(out) > max {
				return nil
			}
		}
	}
	slices.Sort(out)
	return out
}
