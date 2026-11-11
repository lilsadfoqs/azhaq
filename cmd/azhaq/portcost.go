package main

import (
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/lilsadfoqs/azhaq/internal/cdnranges"
	"github.com/lilsadfoqs/azhaq/internal/collectors/portcol"
	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/types"
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
	// What the ceiling is counted with.
	passes    int // the most times a port is asked: 1, and each pass over the ones that did not answer
	nameAddrs int // the most addresses of a name that are scanned; 0: every one it has (-port-all-ips)
	probes    int // the most connects an open port costs after the one that found it
	// The default scan's second pass: every port but the skipped ones, asked of an
	// address that answered, and the ports a URL target adds to an address's first.
	escalate bool
	full     []int
	also     map[string][]int
}

// secondPortsOf is how many ports the second pass of the default scan asks of an
// address: the 65535, less the ports of the first pass and those -port-skip leaves out.
func secondPortsOf(first int, skip []int) int {
	return max(allTCPPorts-len(skip)-first, 0)
}

// listOf is the ports asked of host in the first pass: its own, or the list and the
// ports its URL targets add.
func (m portModel) listOf(host string) []int {
	if own, ok := m.own[host]; ok {
		return own
	}
	if extra := m.also[host]; len(extra) > 0 {
		return unionInts(m.tcp, extra)
	}
	return m.tcp
}

func unionInts(a, b []int) []int {
	all := slices.Concat(a, b)
	slices.Sort(all)
	return slices.Compact(all)
}

// goesOn says whether an address that answers is asked the second pass.
func (m portModel) goesOn(host string, e edge) bool {
	if _, own := m.own[host]; own || !m.escalate || m.threshold > 0 || m.discover == portcol.DiscoverOnly {
		return false
	}
	return !(e == edgeYes && m.excludeCDN)
}

// second is the connects of the second pass of host at ip that the scope allows.
func (m portModel) second(host, ip string) int64 {
	all, _ := m.kept(host, ip, m.full)
	first, _ := m.kept(host, ip, m.listOf(host))
	return int64(max(all-first, 0))
}

func newPortModel(rules scope.Rules, env costEnv) portModel {
	m := portModel{rules: rules, tcp: env.portList, udp: env.portUDPList, own: env.portsFor, discover: env.portDiscover,
		excludeCDN: env.portExcludeCDN, threshold: env.portThreshold, passes: max(env.portPasses, 1), nameAddrs: env.portNameAddrs,
		escalate: env.portEscalate, also: env.portAlso}
	if m.escalate {
		m.full, _ = portscan.Ports("full")
		if len(env.portSkip) > 0 {
			m.full, _ = portscan.Exclude(m.full, portscan.Spec(env.portSkip))
		}
	}
	if env.portDetect == portscan.DetectAll {
		m.probes = portscan.MaxConnectsPerOpenPort
	}
	return m
}

// The ceiling of the port scan is counted as the floor is, with what the
// answers decide given its most: every port asked on every pass, each of them
// open and costing all it may, every datagram asked in each of its four
// passes, and a range's every address up. A CDN or WAF address is counted as
// any other.

// satAdd and satMul keep a ceiling of a very large range from wrapping.
func satAdd(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func satMul(a, b int64) int64 {
	if a != 0 && b > math.MaxInt64/a {
		return math.MaxInt64
	}
	return a * b
}

// ceilOne is the most one address is sent: connects, datagrams.
func (m portModel) ceilOne(host, ip string) (tcp, udp int64) {
	list := m.listOf(host)
	if _, own := m.own[host]; m.escalate && !own && m.discover != portcol.DiscoverOnly {
		list = m.full // every port is asked, if the address answers
	}
	discovery := int64(2 * len(portscan.DiscoveryPorts)) // two tries of each port
	if m.discover == portcol.DiscoverOnly {
		tcp = discovery
	} else if kept, _ := m.kept(host, ip, list); kept > 0 {
		tcp = satMul(int64(kept), int64(m.passes+m.probes))
		if m.discover == portcol.DiscoverFirst {
			tcp += discovery
		}
	}
	if len(m.udp) > 0 && m.discover != portcol.DiscoverOnly {
		k, _ := m.kept(host, ip, m.udp)
		udp = int64(k) * portscan.MaxUDPAsks
	}
	return tcp, udp
}

// ceilHost is the ceiling of a name or an address given as a target: the
// first two addresses of each family of a name, or every one with
// -port-all-ips (open: not known before the name is looked up).
func (m portModel) ceilHost(host string) (c ceiling) {
	if ip := net.ParseIP(host); ip != nil {
		t, u := m.ceilOne(host, ip.String())
		return ceiling{target: t + u}
	}
	if m.nameAddrs == 0 {
		return ceiling{tOpen: []string{"every address of a name is scanned (-port-all-ips)"}}
	}
	t, u := m.ceilOne(host, "")
	return ceiling{target: satMul(t+u, int64(m.nameAddrs))}
}

// ceilSpan is the ceiling of a range given as a target.
func (m portModel) ceilSpan(pf netip.Prefix) ceiling {
	pf = pf.Masked()
	if pf.Addr().Is6() && pf.Bits() < 104 {
		return ceiling{} // portcol refuses it: nothing finishes it
	}
	total := m.rules.CountAddrs(pf)
	var sum int64
	special := map[netip.Addr]bool{}
	for _, a := range m.rules.PortedAddrs(pf) {
		special[a] = true
	}
	for _, hosts := range []map[string][]int{m.own, m.also} {
		for h := range hosts {
			if a, err := netip.ParseAddr(h); err == nil && pf.Contains(a.Unmap()) && m.rules.Allows(a.String()) {
				special[a.Unmap()] = true
			}
		}
	}
	for a := range special {
		t, u := m.ceilOne(a.String(), a.String())
		sum = satAdd(sum, t+u)
		total--
	}
	if total > 0 {
		free := m
		free.rules = scope.Rules{}
		t, u := free.ceilOne("", "")
		if total > math.MaxInt64 {
			total = math.MaxInt64
		}
		sum = satAdd(sum, satMul(t+u, int64(total)))
	}
	return ceiling{target: sum}
}

// ceilOf is the ceiling of the port scan of one target, as portsOf is its
// floor.
func (m portModel) ceilOf(s types.Seed, ranges []netip.Prefix) ceiling {
	switch s.Type {
	case types.TypePrefix:
		if pf, err := netip.ParsePrefix(s.Key()); err == nil {
			return m.ceilSpan(pf)
		}
	case types.TypeIPAddress, types.TypeHostname:
		if a, err := netip.ParseAddr(s.Key()); err == nil {
			for _, pf := range ranges {
				if pf.Contains(a.Unmap()) {
					return ceiling{}
				}
			}
		}
		return m.ceilHost(s.Key())
	}
	return ceiling{}
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
	list := m.listOf(host)
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
	if kept > 0 && asUp && m.goesOn(host, e) {
		tcp += m.second(host, ip)
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
	for _, hosts := range []map[string][]int{m.own, m.also} {
		for h := range hosts {
			if a, err := netip.ParseAddr(h); err == nil && pf.Contains(a.Unmap()) && m.rules.Allows(a.String()) {
				special[a.Unmap()] = true
			}
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

// portPasses is the most times a port is asked with retries as portscan reads
// it: none is one pass, the default policy one more over the ports that did
// not answer, n is n more.
func portPasses(retries int) int {
	switch {
	case retries < 0:
		return 1
	case retries == 0:
		return 2
	}
	return 1 + retries
}

// portNameAddrs is the most addresses of a name the scan asks: two of each
// family (one with -port-ip), every one it has with -port-all-ips (0).
func portNameAddrs(cfg portcol.Config) int {
	switch {
	case cfg.AllIPs:
		return 0
	case cfg.IPv4Only || cfg.IPv6Only:
		return 2
	}
	return 4
}
