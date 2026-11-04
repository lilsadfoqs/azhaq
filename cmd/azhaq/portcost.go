package main

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/lilsadfoqs/azhaq/internal/cdnranges"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/scope"
)

// What the port scan sends at least, counted as the collector asks: the ports
// of each address, less the ones the scope keeps out; a range is every address
// of it the scope allows, none of its blocks or its addresses left out.
//
// The count is a floor. It leaves out what an answer decides (a scan that
// retries, the probes of an open port) and what is not known before the run:
// whether an address of a range is up (-port-discover first asks the ports of
// the addresses that are), and whether a name is behind a CDN or WAF, whose
// addresses get no UDP datagram.

// maxEdgeWalk is the most addresses of a range that are asked, one by one,
// whether they are a CDN's: a larger range that holds one is counted as if
// every address might be.
const maxEdgeWalk = 1 << 16

// portModel is what -ports and its companions fix.
type portModel struct {
	rules      scope.Rules
	tcp, udp   []int
	own        map[string][]int // -ports-on: a host's own ports
	discover   portcol.Discovery
	excludeCDN bool
	threshold  int // -port-threshold: a host is left after this many open ports
}

func newPortModel(rules scope.Rules, env costEnv) portModel {
	return portModel{rules: rules, tcp: env.portList, udp: env.portUDPList, own: env.portsFor, discover: env.portDiscover,
		excludeCDN: env.portExcludeCDN, threshold: env.portThreshold}
}

// kept are the ports of list that may be asked of host at ip; out are the ones
// the scope keeps out (an -allow entry that names another port).
func (m portModel) kept(host, ip string, list []int) (kept, out int) {
	if m.rules.Empty() {
		return len(list), 0
	}
	if !m.rules.HasPortRules() {
		if ip != "" && m.rules.Allows(ip) || host != "" && m.rules.Allows(host) {
			return len(list), 0
		}
		return 0, len(list)
	}
	for _, p := range list {
		ps := strconv.Itoa(p)
		if ip != "" && m.rules.AllowsAddr(ip, ps) || host != "" && host != ip && m.rules.AllowsAddr(host, ps) {
			kept++
		}
	}
	return kept, len(list) - kept
}

// edge says what is known of an address being a CDN's.
type edge int

const (
	edgeNo edge = iota
	edgeYes
	edgeMaybe // a name: its addresses are not known before the run
)

func edgeOf(ip string) edge {
	if name, _ := fingerprint.NetworkEdge(net.ParseIP(ip)); name != "" {
		return edgeYes
	}
	return edgeNo
}

// one is what one address costs at least. host is the name it was given by
// (the address again when it was given as one). asUp: the address is taken
// to answer, as the estimate takes each target given to.
func (m portModel) one(host, ip string, e edge, asUp bool) amount {
	if e == edgeMaybe {
		a, b := m.one(host, ip, edgeNo, asUp), m.one(host, ip, edgeYes, asUp)
		return amount{Connects: min(a.Connects, b.Connects), Datagrams: min(a.Datagrams, b.Datagrams)} // no datagram is certain
	}
	list := m.tcp
	if own, ok := m.own[host]; ok {
		list = own
	}
	if e == edgeYes && m.excludeCDN {
		list = portcol.CDNPorts()
	}
	kept, out := m.kept(host, ip, list)
	var tcp int64
	switch {
	case kept == 0:
	case m.discover == portcol.DiscoverOff || out > 0:
		// A host held to some ports is asked those, with no discovery of its own.
		tcp = int64(m.capped(kept))
	case m.discover == portcol.DiscoverFirst:
		tcp = 2
		if asUp {
			tcp += int64(m.capped(kept))
		}
	default:
		tcp = 2
	}
	var udp int64
	if len(m.udp) > 0 && e == edgeNo && m.discover != portcol.DiscoverOnly && (asUp || m.discover == portcol.DiscoverOff) {
		k, _ := m.kept(host, ip, m.udp)
		udp = int64(k)
	}
	return amount{Connects: tcp, Datagrams: udp}
}

// capped is the ports a host is asked of n when -port-threshold stops it
// after some open ones: at least that many, whichever are open.
func (m portModel) capped(n int) int {
	if m.threshold > 0 {
		return min(n, m.threshold)
	}
	return n
}

// host is a name or an address given as a target: asked as if it answers.
func (m portModel) host(host string) amount {
	if ip := net.ParseIP(host); ip != nil {
		return m.one(host, ip.String(), edgeOf(ip.String()), true)
	}
	return m.one(host, "", edgeMaybe, true)
}

// span is a range given as a target.
func (m portModel) span(pf netip.Prefix) amount {
	pf = pf.Masked()
	if pf.Addr().Is6() && pf.Bits() < 104 {
		return amount{} // portcol refuses it: nothing finishes it
	}
	single := pf.IsSingleIP()
	total := m.rules.CountAddrs(pf)
	var sum amount
	// The addresses the scope names with a port, and those with ports of their
	// own, are asked one by one; the rest of the range is alike.
	special := map[netip.Addr]bool{}
	for _, a := range m.rules.PortedAddrs(pf) {
		special[a] = true
	}
	for h := range m.own {
		if a, err := netip.ParseAddr(h); err == nil && pf.Contains(a.Unmap()) && m.rules.Allows(a.String()) {
			special[a.Unmap()] = true
		}
	}
	for a := range special {
		sum.add(m.one(a.String(), a.String(), edgeOf(a.String()), single))
		total--
	}
	if total == 0 || total > 1<<63 {
		return sum
	}
	// The scope has been asked of each of these: any port of them is allowed.
	free := m
	free.rules = scope.Rules{}
	hold := m.excludeCDN || len(m.udp) > 0
	if !hold || !cdnranges.EdgeOverlaps(pf) {
		sum.add(scaled(free.one("", "", edgeNo, single), total))
		return sum
	}
	if size := uint64(1) << (pf.Addr().BitLen() - pf.Bits()); size <= maxEdgeWalk {
		var edges uint64
		for a := pf.Addr(); pf.Contains(a); a = a.Next() {
			if !special[a] && m.rules.Allows(a.String()) && edgeOf(a.String()) == edgeYes {
				edges++
			}
		}
		sum.add(scaled(free.one("", "", edgeYes, single), edges))
		sum.add(scaled(free.one("", "", edgeNo, single), total-edges))
		return sum
	}
	// Too many addresses to ask each: any of them may be a CDN's.
	sum.add(scaled(free.one("", "", edgeMaybe, single), total))
	return sum
}

func scaled(a amount, n uint64) amount {
	return amount{Connects: a.Connects * int64(n), Datagrams: a.Datagrams * int64(n)}
}
