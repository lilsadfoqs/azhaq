package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// addrPorts is what one run's port scans found at one address. The address
// is the identity, whichever seed asked (a name, the address, a range): a
// range stores its addresses' rows under the range, a name under the name,
// and which one reaches an address first changes from run to run.
type addrPorts struct {
	ports    []string // open TCP ports, in order
	svcs     []portSvc
	names    []string // the names a scan of the address was asked for
	complete bool     // a scan of the address finished; else only checkpoints of one a limit stopped
}

// runPorts is a run's port scans: per address, and the ranges it finished,
// whose addresses with no row had nothing open.
type runPorts struct {
	addrs  map[string]*addrPorts
	ranges []netip.Prefix
}

func scansOf(st *store.Store) runPorts {
	out := runPorts{addrs: map[string]*addrPorts{}}
	obs, _ := st.Observations()
	for _, o := range obs {
		if o.Collector != "azhaq-ports" {
			continue
		}
		var row struct {
			IP      string `json:"ip"`
			Host    string `json:"host"`
			Range   bool   `json:"range"`
			Prefix  string `json:"prefix"`
			Stopped bool   `json:"stopped"`
			Partial bool   `json:"partial"`
			Scanned int    `json:"scanned"`
			Open    []int  `json:"open"`
		}
		if json.Unmarshal(o.Payload, &row) != nil {
			continue
		}
		if row.Range {
			if pf, err := netip.ParsePrefix(row.Prefix); err == nil && !row.Stopped && row.Scanned > 0 {
				out.ranges = append(out.ranges, pf.Masked())
			}
			continue
		}
		if row.IP == "" || row.Scanned == 0 {
			continue // not scanned (no IPv6 route): nothing to compare
		}
		a := out.addrs[row.IP]
		if a == nil {
			a = &addrPorts{ports: []string{}}
			out.addrs[row.IP] = a
		}
		for _, p := range row.Open {
			if s := strconv.Itoa(p); !slices.Contains(a.ports, s) {
				a.ports = append(a.ports, s)
			}
		}
		a.svcs = mergeSvcs(a.svcs, svcsOf(o.Payload))
		a.complete = a.complete || !row.Partial
		if h := strings.ToLower(row.Host); h != "" && h != row.IP && !slices.Contains(a.names, h) {
			a.names = append(a.names, h)
		}
	}
	for _, a := range out.addrs {
		sort.Slice(a.ports, func(i, j int) bool {
			x, _ := strconv.Atoi(a.ports[i])
			y, _ := strconv.Atoi(a.ports[j])
			return x < y
		})
	}
	return out
}

// at is what the run knows of an address: its scans, or, for an address of a
// range the run finished with no row of its own, a complete scan with nothing open.
func (r runPorts) at(ip string) (*addrPorts, bool) {
	if a, ok := r.addrs[ip]; ok {
		return a, true
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		for _, pf := range r.ranges {
			if pf.Contains(addr) {
				return &addrPorts{ports: []string{}, complete: true}, true
			}
		}
	}
	return nil, false
}

// namesByAddress maps an address to the names that resolved to it in a run.
func namesByAddress(st *store.Store, f map[string]facts) map[string][]string {
	out := map[string][]string{}
	ents, _ := st.Entities()
	for _, e := range ents {
		if e.Type != types.TypeHostname {
			continue
		}
		for _, ip := range f[e.ID].ips {
			if !slices.Contains(out[ip], e.Key) {
				out[ip] = append(out[ip], e.Key)
			}
		}
	}
	for _, ns := range out {
		sort.Strings(ns)
	}
	return out
}

// addrLabel names an address on a line: its names (three at most) and the
// address, or the address alone.
func addrLabel(ip string, names []string) string {
	if len(names) == 0 {
		return ip
	}
	shown := names
	more := ""
	if len(shown) > 3 {
		shown, more = shown[:3], fmt.Sprintf(" +%d", len(names)-3)
	}
	return strings.Join(shown, ", ") + more + " (" + ip + ")"
}

// portsChanges are the lines of the addresses whose open TCP ports differ
// between two runs, and of the ports open in both whose product differs.
// A port is new only against a finished scan of the old run, and gone only
// against a finished scan of the new one: a scan a limit stopped saw a part.
func portsChanges(old, neu runPorts, names map[string][]string) (ports, changed []string) {
	label := func(ip string) string {
		all := slices.Clone(names[ip])
		for _, r := range []runPorts{neu, old} {
			if a, ok := r.addrs[ip]; ok {
				for _, n := range a.names {
					if !slices.Contains(all, n) {
						all = append(all, n)
					}
				}
			}
		}
		sort.Strings(all)
		return addrLabel(ip, all)
	}
	for ip, n := range neu.addrs {
		o, ok := old.at(ip)
		if !ok {
			continue
		}
		label := label(ip)
		if line := portsChange(o, n, label); line != "" {
			ports = append(ports, line)
		}
		changed = append(changed, svcChanges(o, n, label)...)
	}
	for ip, o := range old.addrs {
		if _, ok := neu.addrs[ip]; ok || len(o.ports) == 0 || !o.complete {
			continue
		}
		if n, ok := neu.at(ip); ok { // the new run finished the range: nothing is open there now
			if line := portsChange(o, n, label(ip)); line != "" {
				ports = append(ports, line)
			}
		}
	}
	return ports, changed
}

// svcsAt are the services the run found at a name's addresses.
func svcsAt(r runPorts, ips []string) []portSvc {
	var out []portSvc
	for _, ip := range ips {
		if a, ok := r.addrs[ip]; ok {
			out = mergeSvcs(out, a.svcs)
		}
	}
	return out
}
