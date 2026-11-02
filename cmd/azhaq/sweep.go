package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// -sweep: the scope a run was given (-allow, -scope) is more than the
// targets it names. A target list inside a range is scanned as given; the
// rest of the range is covered only when -sweep says so, and a note says
// how much it leaves when the targets name some of it. -allow and -scope
// are a fence the user drew, not a list to scan: a program's scope holds
// ranges of millions, and a run of one host must not turn into a sweep of
// them unasked.

// allowedAddrs are the IPv4 ranges and addresses that allow rules name, as
// sorted, merged ranges; v6 are the IPv6 ranges, which -sweep leaves alone.
func allowedAddrs(rules []string) (v4 []ipRange, v6 []netip.Prefix) {
	for _, r := range rules {
		r = strings.TrimSpace(r)
		var pf netip.Prefix
		if p, err := netip.ParsePrefix(r); err == nil {
			pf = p.Masked()
		} else if a, err := netip.ParseAddr(r); err == nil {
			a = a.Unmap()
			pf = netip.PrefixFrom(a, a.BitLen())
		} else {
			continue
		}
		if !pf.Addr().Is4() {
			if !pf.IsSingleIP() {
				v6 = append(v6, pf)
			}
			continue
		}
		v4 = append(v4, prefixRange(pf))
	}
	return mergeRanges(v4), v6
}

func prefixRange(pf netip.Prefix) ipRange {
	lo := binary.BigEndian.Uint32(pf.Addr().AsSlice())
	return ipRange{lo, lo + uint32(uint64(1)<<(32-pf.Bits())-1)}
}

func mergeRanges(rs []ipRange) []ipRange {
	rs = append([]ipRange(nil), rs...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	var out []ipRange
	for _, r := range rs {
		if n := len(out); n > 0 && uint64(r.lo) <= uint64(out[n-1].hi)+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

// subtractRanges is a without b; both are merged.
func subtractRanges(a, b []ipRange) []ipRange {
	var out []ipRange
	for _, r := range a {
		lo, done := uint64(r.lo), false
		for _, d := range b {
			if d.hi < r.lo || d.lo > r.hi {
				continue
			}
			if uint64(d.lo) > lo {
				out = append(out, ipRange{uint32(lo), d.lo - 1})
			}
			lo = max(lo, uint64(d.hi)+1)
			if lo > uint64(r.hi) {
				done = true
				break
			}
		}
		if !done {
			out = append(out, ipRange{uint32(lo), r.hi})
		}
	}
	return out
}

func intersectRanges(a, b []ipRange) []ipRange {
	var out []ipRange
	for _, x := range a {
		for _, y := range b {
			if lo, hi := max(x.lo, y.lo), min(x.hi, y.hi); lo <= hi {
				out = append(out, ipRange{lo, hi})
			}
		}
	}
	return mergeRanges(out)
}

func countRanges(rs []ipRange) (n uint64) {
	for _, r := range rs {
		n += uint64(r.hi) - uint64(r.lo) + 1
	}
	return n
}

// namedAddrs are the IPv4 addresses and ranges the seeds name: an address
// or a URL on one, or a range. A name is not resolved for this.
func namedAddrs(seeds []types.Seed) []ipRange {
	var out []ipRange
	for _, s := range seeds {
		s = normalize.Seed(s)
		host := ""
		switch s.Type {
		case types.TypePrefix:
			if pf, err := netip.ParsePrefix(s.Key()); err == nil && pf.Addr().Is4() {
				out = append(out, prefixRange(pf.Masked()))
			}
			continue
		case types.TypeURL:
			if u, err := url.Parse(s.Key()); err == nil {
				host = u.Hostname()
			}
		case types.TypeIPAddress, types.TypeHostname:
			host = s.Key()
		}
		if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && a.Unmap().Is4() {
			out = append(out, prefixRange(netip.PrefixFrom(a.Unmap(), 32)))
		}
	}
	return mergeRanges(out)
}

// sweepSeeds are the targets -sweep adds: each range or address the allow
// rules name, less the ones already a target. Addresses a deny rule holds
// are refused one by one, as for any target, and counted.
func sweepSeeds(allow []string, have []types.Seed) (seeds []types.Seed, v6 []netip.Prefix, err error) {
	v4, v6 := allowedAddrs(allow)
	if len(v4) == 0 {
		return nil, nil, usagef("-sweep covers the IPv4 ranges and addresses -allow and -scope hold, and they hold none: give -allow 192.0.2.0/24 (a domain names no address to sweep)")
	}
	seen := map[string]bool{}
	for _, s := range have {
		seen[normalize.Seed(s).Key()] = true
	}
	for _, r := range v4 {
		for _, pf := range cover([]ipRange{r}) {
			var s types.Seed
			if pf.IsSingleIP() {
				if s, err = listSeed(pf.Addr().String()); err != nil {
					return nil, nil, err
				}
			} else {
				s = types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": pf.String()}}
			}
			if k := normalize.Seed(s).Key(); !seen[k] {
				seen[k] = true
				seeds = append(seeds, s)
			}
		}
	}
	return seeds, v6, nil
}

// sweepLead is the note for a run whose targets name some addresses of the
// range its scope allows and not the rest, or "". It counts what the scope
// allows less what it denies, and says what -sweep would add.
func sweepLead(allow, deny []string, named []ipRange) string {
	allowed, _ := allowedAddrs(allow)
	denied, _ := allowedAddrs(deny)
	open := subtractRanges(allowed, denied)
	have := countRanges(intersectRanges(open, named))
	total := countRanges(open)
	if have == 0 || total <= have {
		return ""
	}
	return fmt.Sprintf("the scope (-allow, -scope) holds %s addresses and the targets name %s of them: -sweep covers the other %s, within -deny, -rate and -max-requests",
		humanCount(float64(total)), humanCount(float64(have)), humanCount(float64(total-have)))
}
