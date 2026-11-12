package portcol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// The default scan has two passes: the ports of portscan.DefaultPorts on every
// address, then every other TCP port of each address that answered, which is one
// with an open port. An address that answered nothing is not asked again.

var fullPorts = sync.OnceValue(func() []int {
	all := make([]int, 65535)
	for i := range all {
		all[i] = i + 1
	}
	return all
})

// passOf is n when the scan has two passes, else 0 (no pass is named).
func (c *Collector) passOf(n int) int {
	if c.Escalate {
		return n
	}
	return 0
}

// escalates says whether an address goes on to the second pass: the scan has one,
// the address answered (an open port in this run's first pass, or in the stopped
// run's one), and was not held to ports of its own, to the web ports of a CDN or
// to a threshold of open ports. key is the name its ports are looked up under.
func (c *Collector) escalates(key string, edge bool, s *scan, prior Prior) bool {
	if !c.Escalate || !s.up || s.capped || c.Discover == DiscoverOnly || edge && c.ExcludeCDN {
		return false
	}
	if _, own := c.PortsFor[key]; own {
		return false
	}
	return len(s.open) > 0 || len(prior.Open) > 0
}

// rest are the ports the second pass asks of an address: every one that the first
// pass (all) and a stopped run (prior) did not, the scope allows and -ep leaves in.
func (c *Collector) rest(host, ip string, all []int, prior Prior) []int {
	out := without(without(fullPorts(), all), prior.Asked)
	if len(c.NoPorts) > 0 {
		out = slices.DeleteFunc(out, func(p int) bool { return c.NoPorts[p] })
	}
	out, _ = inScope(host, ip, out)
	return out
}

// second is the second pass of an address that answered: it asks the ports rest
// gives and adds what answers to s. A limit that stops it is s's error, and s
// says how far it went (asked2). The ports the first pass asked (ports) are
// kept in the row it leaves, so that a resume asks the rest and no more.
func (c *Collector) second(ctx context.Context, emit func(types.Observation) error, host, ip string, all, ports []int, prior Prior, resumed bool, s *scan, name string, edge bool, prefix string, found func(portscan.Open)) {
	s.pass2 = true
	s.rest = c.rest(host, ip, all, prior)
	if len(s.rest) == 0 {
		return
	}
	prior2 := Prior{Asked: append(slices.Clone(prior.Asked), ports...), Open: slices.Clone(s.open)}
	if resumed {
		prior2.Open = append(slices.Clone(prior.Open), s.open...)
	}
	// The first pass is kept now: what answered, and that the second has not begun.
	cp := c.checkpoint(emit, host, ip, s.rest, prior2, true, name, edge, prefix, 2)
	cp(portscan.Progress{})
	r, err := c.Scanner.ScanEachFn(portscan.WithProgress(ctx, cp), host, ip, s.rest, found)
	s.open = append(s.open, r.Open...)
	sort.Slice(s.open, func(i, j int) bool { return s.open[i].Port < s.open[j].Port })
	s.silent = append(s.silent, r.Silent...)
	s.unprobed += r.Unprobed
	s.capped = s.capped || r.Threshold
	s.asked2, s.err = r.Asked, err
}

// all is every port an address was asked when it went on to the second pass.
func (c *Collector) allAsked(host, ip string, all []int) []int {
	return slices.Concat(all, c.rest(host, ip, all, Prior{}))
}

// CutNote says what a limit left of the default scan's passes, from the rows of
// the scans it stopped: the addresses and ports of the pass it cut, and what the
// other pass had not begun. "" when no row names a pass.
func CutNote(obs []types.StoredObservation) string {
	byIP := map[string]struct{ pass, ports int }{}
	blocks := map[string]struct{ pass, of, asked int }{}
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "ports" {
			continue
		}
		var row struct {
			IP      string `json:"ip"`
			Partial bool   `json:"partial"`
			Range   bool   `json:"range"`
			Stopped bool   `json:"stopped"`
			Prefix  string `json:"prefix"`
			Pass    int    `json:"pass"`
			Left    int    `json:"ports_left"`
			Of      int    `json:"addresses_of"`
			Addrs   int    `json:"addresses"`
		}
		if json.Unmarshal(o.Payload, &row) != nil {
			continue
		}
		switch {
		case row.Range:
			if row.Stopped && row.Pass > 0 {
				blocks[row.Prefix] = struct{ pass, of, asked int }{row.Pass, row.Of, row.Addrs}
			} else if !row.Stopped {
				delete(blocks, row.Prefix)
			}
		case row.IP == "":
		case row.Partial && row.Pass > 0:
			byIP[row.IP] = struct{ pass, ports int }{row.Pass, row.Left}
		default:
			delete(byIP, row.IP) // a whole scan came after it
		}
	}
	var pass [3]struct{ addrs, ports int }
	for _, r := range byIP {
		pass[r.pass].addrs++
		pass[r.pass].ports += r.ports
	}
	unreached := 0
	for _, b := range blocks {
		if b.pass == 1 {
			unreached += max(b.of-b.asked, 0)
		}
	}
	var parts []string
	if p := pass[1]; p.addrs > 0 || unreached > 0 {
		s := fmt.Sprintf("pass 1 of 2 (%d ports of each address) was cut: %s with ports left (%s not asked)", len(portscan.DefaultPorts()), nOf(p.addrs, "address", "addresses"), nOf(p.ports, "port", "ports"))
		if unreached > 0 {
			s += fmt.Sprintf(", and %s of the range not reached", nOf(unreached, "address", "addresses"))
		}
		parts = append(parts, s+"; pass 2, every port of each address that answers, had not begun there")
	}
	if p := pass[2]; p.addrs > 0 {
		parts = append(parts, fmt.Sprintf("pass 2 of 2 (every port of the addresses that answered pass 1) was cut: %s with ports left (%s not asked)", nOf(p.addrs, "address", "addresses"), nOf(p.ports, "port", "ports")))
	}
	return strings.Join(parts, "; ")
}

func nOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// NotAsked counts, from the rows of the scans a limit stopped, the addresses
// that still have ports not asked and those ports: the addresses a stopped scan
// left part-asked (a row says how many ports it had left, or which it asked of
// the first ports ports), and those of a stopped block it never reached, which
// have all of the first ports left. An address its block lists as finished has
// none left, whatever its last checkpoint said.
func NotAsked(obs []types.StoredObservation, first int) (addrs, ports int) {
	type left struct {
		prefix string
		ports  int
	}
	byIP := map[string]left{}
	blocks := map[string]int{}         // prefix → addresses of it not reached
	swept := map[string]map[int]bool{} // prefix → places of the addresses it finished
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "ports" {
			continue
		}
		var row struct {
			IP      string `json:"ip"`
			Partial bool   `json:"partial"`
			Range   bool   `json:"range"`
			Stopped bool   `json:"stopped"`
			Prefix  string `json:"prefix"`
			Pass    int    `json:"pass"`
			Left    int    `json:"ports_left"`
			Asked   string `json:"asked_ports"`
			Swept   string `json:"swept"`
			Of      int    `json:"addresses_of"`
			Addrs   int    `json:"addresses"`
		}
		if json.Unmarshal(o.Payload, &row) != nil {
			continue
		}
		switch {
		case row.Range:
			if row.Stopped {
				if done, err := places(row.Swept); err == nil {
					set := make(map[int]bool, len(done))
					for _, n := range done {
						set[n] = true
					}
					swept[row.Prefix] = set
				}
				if row.Of > 0 {
					blocks[row.Prefix] = max(row.Of-row.Addrs, 0)
				}
			} else {
				delete(blocks, row.Prefix)
				delete(swept, row.Prefix)
			}
		case row.IP == "":
		case row.Partial:
			n := row.Left
			if row.Pass == 0 {
				done, _ := places(row.Asked)
				n = max(first-len(done), 0)
			}
			byIP[row.IP] = left{row.Prefix, n}
		default:
			delete(byIP, row.IP) // a whole scan came after it
		}
	}
	for ip, l := range byIP {
		if l.ports == 0 || finishedIn(swept[l.prefix], l.prefix, ip) {
			continue
		}
		addrs++
		ports += l.ports
	}
	for _, n := range blocks {
		addrs += n
		ports += n * first
	}
	return addrs, ports
}

// finishedIn says whether the block prefix lists ip, by its place in it, as finished.
func finishedIn(set map[int]bool, prefix, ip string) bool {
	pf, err := netip.ParsePrefix(prefix)
	a, err2 := netip.ParseAddr(ip)
	if len(set) == 0 || err != nil || err2 != nil || !pf.Contains(a) {
		return false
	}
	at := 1
	for b := pf.Masked().Addr(); b != a; b = b.Next() {
		at++
	}
	return set[at]
}
