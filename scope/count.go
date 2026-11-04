package scope

import (
	"encoding/binary"
	"net/netip"
	"slices"
)

// span is a run of addresses of a prefix, as offsets from its first address.
type span struct{ lo, hi uint64 }

func (r Rules) sets() (allow, deny ruleSet) {
	if r.idx != nil {
		return r.idx.allow, r.idx.deny
	}
	return compileSet(r.Allow), compileSet(r.Deny)
}

// offset is where a is in pf, which holds it.
func offset(pf netip.Prefix, a netip.Addr) uint64 {
	lo := func(x netip.Addr) uint64 {
		b := x.As16()
		return binary.BigEndian.Uint64(b[8:])
	}
	return lo(a) - lo(pf.Addr())
}

// spansIn are the addresses of pf that a set of rules holds by range or by
// address (a domain rule names no address), as merged spans.
func spansIn(set ruleSet, pf netip.Prefix, size uint64) []span {
	var out []span
	for _, n := range set.nets {
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		np := netip.PrefixFrom(a, ones)
		if np.Addr().Is4() != pf.Addr().Is4() {
			continue
		}
		switch {
		case np.Bits() <= pf.Bits() && np.Contains(pf.Addr()):
			out = append(out, span{0, size - 1})
		case np.Bits() > pf.Bits() && pf.Contains(np.Addr()):
			o := offset(pf, np.Addr())
			out = append(out, span{o, o + uint64(1)<<(np.Addr().BitLen()-np.Bits()) - 1})
		}
	}
	for host := range set.exact {
		if a, err := netip.ParseAddr(host); err == nil && pf.Contains(a.Unmap()) {
			o := offset(pf, a.Unmap())
			out = append(out, span{o, o})
		}
	}
	return merge(out)
}

func merge(in []span) []span {
	slices.SortFunc(in, func(a, b span) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	var out []span
	for _, s := range in {
		if n := len(out); n > 0 && s.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, s.hi)
			continue
		}
		out = append(out, s)
	}
	return out
}

func total(in []span) uint64 {
	var n uint64
	for _, s := range in {
		n += s.hi - s.lo + 1
	}
	return n
}

// overlap is how many addresses two merged lists of spans share.
func overlap(a, b []span) uint64 {
	var n uint64
	for i, j := 0, 0; i < len(a) && j < len(b); {
		lo, hi := max(a[i].lo, b[j].lo), min(a[i].hi, b[j].hi)
		if lo <= hi {
			n += hi - lo + 1
		}
		if a[i].hi < b[j].hi {
			i++
		} else {
			j++
		}
	}
	return n
}

// CountAddrs is how many addresses of pf the rules allow, counted without
// asking about each: the addresses an allow entry holds (all of them when
// there is none) less those a deny entry holds. A prefix with more than 2^63
// addresses counts as that many.
func (r Rules) CountAddrs(pf netip.Prefix) uint64 {
	pf = pf.Masked()
	bits := pf.Addr().BitLen() - pf.Bits()
	if bits > 63 {
		return 1 << 63
	}
	size := uint64(1) << bits
	if r.Empty() {
		return size
	}
	allow, deny := r.sets()
	held := []span{{0, size - 1}}
	if len(r.Allow) > 0 {
		held = spansIn(allow, pf, size)
	}
	return total(held) - overlap(held, spansIn(deny, pf, size))
}

// PortedAddrs are the addresses of pf an allow entry names with a port
// (127.0.0.1:3001) that the rules allow: the ones where which ports are
// allowed has to be asked, as the other addresses of pf take any port.
func (r Rules) PortedAddrs(pf netip.Prefix) []netip.Addr {
	pf = pf.Masked()
	allow, _ := r.sets()
	var out []netip.Addr
	for host := range allow.exactPorts {
		a, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		if a = a.Unmap(); pf.Contains(a) && r.Allows(a.String()) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// HasPortRules says an allow entry names a port.
func (r Rules) HasPortRules() bool {
	allow, _ := r.sets()
	return len(allow.exactPorts) > 0 || len(allow.suffixPorts) > 0
}
