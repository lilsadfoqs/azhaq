package portcol

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// udpScan is one address's UDP scan, shared by the names that point to it.
type udpScan struct {
	done chan struct{}
	rep  portscan.UDPReport
	err  error
}

// scanUDPOnce scans an address's UDP ports once, however many names
// point to it.
func (c *Collector) scanUDPOnce(ctx context.Context, host, ip string) (portscan.UDPReport, error) {
	c.mu.Lock()
	if c.udpByIP == nil {
		c.udpByIP = map[string]*udpScan{}
	}
	s, ok := c.udpByIP[ip]
	if !ok {
		s = &udpScan{done: make(chan struct{})}
		c.udpByIP[ip] = s
	}
	c.mu.Unlock()
	if ok {
		select {
		case <-s.done:
			return s.rep, s.err
		case <-ctx.Done():
			return portscan.UDPReport{}, ctx.Err()
		}
	}
	ports, _ := inScope(host, ip, c.UDPPorts) // UDP ports are held to -allow HOST:PORT as TCP ones are
	if len(ports) > 0 {
		s.rep, s.err = c.Scanner.ScanUDPFrom(ctx, host, ip, ports, c.Prior[ip].UDP)
	}
	if s.err != nil {
		recordStops(ip, s.rep.Stopped)
	}
	close(s.done)
	return s.rep, s.err
}

// scanUDPGated is ScanUDPFrom for an address of a range, run when one of the
// UDP scans the rate can keep busy is free: with a cap or a stop the first
// addresses of the range are finished, and a resume goes on from there.
func (c *Collector) scanUDPGated(ctx context.Context, ip string, ports []int, prior portscan.UDPPrior) (portscan.UDPReport, error) {
	c.mu.Lock()
	if c.udpGate == nil {
		c.udpGate = make(chan struct{}, c.Scanner.UDPHosts())
	}
	gate := c.udpGate
	c.mu.Unlock()
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return portscan.UDPReport{}, ctx.Err()
	}
	defer func() { <-gate }()
	return c.Scanner.ScanUDPFrom(ctx, ip, ip, ports, prior)
}

var stops struct {
	sync.Mutex
	byIP map[string][]portscan.UDPStop
}

// recordStops keeps the UDP ports a stopped scan left unfinished: the
// stopped run cannot write a row, so the summary reads them from here.
func recordStops(ip string, list []portscan.UDPStop) {
	if len(list) == 0 {
		return
	}
	stops.Lock()
	defer stops.Unlock()
	if stops.byIP == nil {
		stops.byIP = map[string][]portscan.UDPStop{}
	}
	stops.byIP[ip] = list
}

// StoppedNotes says, for each address whose UDP scan a limit, a signal or
// -timeout stopped, how many of its payloads were asked of each port that
// has not answered. It clears what it read.
func StoppedNotes() []string {
	stops.Lock()
	by := stops.byIP
	stops.byIP = nil
	stops.Unlock()
	ips := make([]string, 0, len(by))
	for ip := range by {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var out []string
	for _, ip := range ips {
		var named []string
		untouched := 0
		for _, st := range by[ip] {
			if st.Asked == 0 {
				untouched++
				continue
			}
			named = append(named, fmt.Sprintf("%s/udp: %d of %d payloads asked before the run stopped; no answer yet, so open|filtered is not final", net.JoinHostPort(ip, strconv.Itoa(st.Port)), st.Asked, st.Of))
		}
		if len(named) > 3 {
			out = append(out, named[:3]...)
			out = append(out, fmt.Sprintf("%s: %d more UDP ports asked only part of their payloads (not final); azhaq resume asks the rest", ip, len(named)-3))
		} else {
			out = append(out, named...)
		}
		if untouched > 0 {
			out = append(out, fmt.Sprintf("%s: %d UDP %s not asked before the run stopped", ip, untouched, plural(untouched, "port")))
		}
	}
	return out
}

// maxClosedListed: a row names this many of an address's closed UDP ports,
// the count says the rest (a full scan of a host that refuses them all
// would be 65535 numbers).
const maxClosedListed = 16

// addUDP puts what a UDP scan found in a name's row: the ports by state,
// and what each answer said. Silent ports are listed in udp_services (the
// rows a command prints) up to maxListed per address; past it the row's
// udp_open_filtered still has them all, and udp_unlisted says so.
func addUDP(row map[string]any, r portscan.UDPReport, scanned int) {
	open, filtered := []int{}, []int{}
	var services []portscan.UDPPort
	for _, u := range r.Open {
		open = append(open, u.Port)
		services = append(services, u)
	}
	for _, u := range r.OpenFiltered {
		filtered = append(filtered, u.Port)
	}
	if len(r.OpenFiltered) <= maxListed {
		services = append(services, r.OpenFiltered...)
	} else {
		row["udp_unlisted"] = len(r.OpenFiltered)
	}
	row["udp_scanned"] = scanned
	row["udp_open"] = open
	row["udp_open_filtered"] = filtered
	row["udp_closed"] = r.Closed
	if len(r.ClosedPorts) > 0 {
		row["udp_closed_ports"] = r.ClosedPorts[:min(len(r.ClosedPorts), maxClosedListed)]
	}
	if r.Limited > 0 {
		row["udp_limited"] = r.Limited
	}
	if len(services) > 0 {
		row["udp_services"] = services
	}
	if len(r.Stopped) > 0 {
		addUDPStop(row, r)
	}
}

// SilentOnlyKey marks the row of an address in a range that answered nothing
// on UDP: it holds only the ports it was asked, in udp_open_filtered. Output
// lists these ports only when asked, and the summary counts them from the
// range's row.
const SilentOnlyKey = "udp_silent_only"

// silentRow is the row of an address of a range whose every UDP port stayed
// silent.
func silentRow(ip, prefix string, r portscan.UDPReport, scanned int) map[string]any {
	ports := make([]int, 0, len(r.OpenFiltered))
	for _, u := range r.OpenFiltered {
		ports = append(ports, u.Port)
	}
	return map[string]any{"host": ip, "ip": ip, "prefix": prefix, SilentOnlyKey: true, "udp_scanned": scanned, "udp_open_filtered": ports}
}

// udpRow is addUDP for a row of this collector's scan, which also says when
// each port was asked one request only.
func (c *Collector) udpRow(row map[string]any, r portscan.UDPReport, scanned int) {
	addUDP(row, r, scanned)
	if c.Scanner.Detect == portscan.DetectNone {
		row[udpOneKey] = true
	}
}

// UDP fields of a row a limit stopped: the ports refused (all of them),
// how many requests each port that is not decided was asked (requests
// asked: the ports), and how many ports that is.
const (
	udpRefusedKey    = "udp_refused"
	udpAskedKey      = "udp_asked"
	udpUnfinishedKey = "udp_unfinished"
	udpUnaskedKey    = "udp_unasked"
	udpOneKey        = "udp_one_request"
)

// addUDPStop says what a stopped UDP scan settled and how far it asked the
// rest, which azhaq resume reads back (Priors).
func addUDPStop(row map[string]any, r portscan.UDPReport) {
	if len(r.ClosedPorts) > 0 {
		row[udpRefusedKey] = portscan.Compact(r.ClosedPorts)
	}
	by := map[int][]int{}
	unasked, unfinished := 0, 0
	for _, st := range r.Stopped {
		if st.Asked == 0 {
			unasked++
			continue
		}
		by[st.Asked] = append(by[st.Asked], st.Port)
		unfinished++
	}
	if len(by) > 0 {
		asked := map[string]string{}
		for n, ports := range by {
			asked[strconv.Itoa(n)] = portscan.Compact(ports)
		}
		row[udpAskedKey] = asked
	}
	if unfinished > 0 {
		row[udpUnfinishedKey] = unfinished
	}
	if unasked > 0 {
		row[udpUnaskedKey] = unasked
	}
}

// udpPrior reads, from the fields of a row a limit stopped, what its UDP
// scan had settled.
func udpPrior(services []portscan.UDPPort, refused string, asked map[string]string, filtered []int) portscan.UDPPrior {
	var pr portscan.UDPPrior
	for _, u := range services {
		if u.State == portscan.UDPOpen {
			pr.Open = append(pr.Open, u)
		}
	}
	pr.Closed, _ = places(refused)
	pr.Asked = map[int]int{}
	for k, v := range asked {
		n, err := strconv.Atoi(k)
		ports, perr := places(v)
		if err != nil || perr != nil {
			continue
		}
		for _, p := range ports {
			pr.Asked[p] = n
		}
	}
	for _, p := range filtered {
		if _, undecided := pr.Asked[p]; !undecided {
			pr.Silent = append(pr.Silent, p)
		}
	}
	return pr
}

// UDPUnfinished are the ports of a stopped row whose open|filtered is not
// final: they were asked only some of their requests.
func UDPUnfinished(row map[string]any) map[int]bool {
	out := map[int]bool{}
	asked, _ := row[udpAskedKey].(map[string]any)
	for _, v := range asked {
		spec, _ := v.(string)
		ports, _ := places(spec)
		for _, p := range ports {
			out[p] = true
		}
	}
	return out
}

// udpSummary is what the rows of a run say of UDP ports that stayed
// silent, read back for the summary.
type udpSummary struct {
	ports     map[string]map[int]bool // address: open|filtered ports (two rows of an address count once)
	unlisted  []string                // addresses with more silent ports than a row lists
	silentN   int                     // silent ports of range addresses that answered nothing, not listed
	silentIPs int                     // those addresses
	limited   int
	once      bool                 // a row asked each port one request only (-detect none)
	closed    map[string]closedUDP // address: the ports it refused
	// Addresses of the ranges that showed nothing else but refused UDP ports.
	closedN, closedIPs int
}

// closedUDP is how many UDP ports an address refused and the first of them.
type closedUDP struct {
	n     int
	ports []int
}

func (u *udpSummary) add(ip string, filtered []int, unlisted, limited int) {
	if len(filtered) > 0 {
		if u.ports == nil {
			u.ports = map[string]map[int]bool{}
		}
		if u.ports[ip] == nil {
			u.ports[ip] = map[int]bool{}
		}
		for _, p := range filtered {
			u.ports[ip][p] = true
		}
	}
	if unlisted > 0 && !slices.Contains(u.unlisted, ip) {
		u.unlisted = append(u.unlisted, ip)
	}
	u.limited += limited
}

// addClosed notes the UDP ports an address refused (an ICMP port
// unreachable); two rows of an address, one for each name, count once.
func (u *udpSummary) addClosed(ip string, n int, ports []int) {
	if n <= 0 {
		return
	}
	if u.closed == nil {
		u.closed = map[string]closedUDP{}
	}
	if c := u.closed[ip]; n > c.n {
		u.closed[ip] = closedUDP{n, ports}
	}
}

// notes say what open|filtered means, once, how many ports are rows, and
// when a host that refused some ports may have rate-limited its refusals.
func (u *udpSummary) notes() []string {
	var out []string
	rows := 0
	for ip, ps := range u.ports {
		if !slices.Contains(u.unlisted, ip) {
			rows += len(ps)
		}
	}
	if rows > 0 {
		asked := "every request its protocol has"
		if u.once {
			asked = "the one request -detect none sends each port"
		}
		out = append(out, fmt.Sprintf("%d UDP %s open|filtered: no reply and no ICMP port unreachable after %s (a silent service or a firewall); a closed port answers with an ICMP error", rows, plural(rows, "port"), asked))
	}
	if n, list := u.closedList(); n > 0 {
		out = append(out, fmt.Sprintf("%d UDP %s closed (ICMP port unreachable): %s", n, plural(n, "port"), list))
	}
	if u.closedIPs > 0 {
		out = append(out, fmt.Sprintf("%d addresses of the ranges refused UDP ports (ICMP port unreachable, %d ports closed in all) and showed nothing else: they are not listed", u.closedIPs, u.closedN))
	}
	if len(u.unlisted) > 0 {
		sort.Strings(u.unlisted)
		var n int
		for _, ip := range u.unlisted {
			n += len(u.ports[ip])
		}
		out = append(out, fmt.Sprintf("%d UDP ports open|filtered on %s are not listed one by one (more than %d on an address: it ignores UDP, or a filter drops it); the workspace row keeps them in udp_open_filtered", n, listOf(u.unlisted, 3), maxListed))
	}
	if u.silentIPs > 0 {
		each := ""
		if u.silentN%u.silentIPs == 0 {
			each = fmt.Sprintf("%d %s asked of each, ", u.silentN/u.silentIPs, plural(u.silentN/u.silentIPs, "port"))
		}
		out = append(out, fmt.Sprintf("%d addresses of the ranges answered no UDP port (no reply, no ICMP port unreachable; %s%d ports open|filtered in all) and are not listed: a host that is down or drops UDP reads this way; -udp-rows lists them, and the workspace keeps each address's ports in its row's udp_open_filtered", u.silentIPs, each, u.silentN))
	}
	if u.limited > 0 {
		out = append(out, fmt.Sprintf("udp: %d silent ports on a host that refused others were not asked again at its ICMP rate limit (about one reply a second; too many for that): some of them may be closed, so scan fewer ports to be sure", u.limited))
	}
	return out
}

// closedList is how many ports were refused, and a few as address:port.
func (u *udpSummary) closedList() (int, string) {
	ips := make([]string, 0, len(u.closed))
	for ip := range u.closed {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var all []string
	total := 0
	for _, ip := range ips {
		c := u.closed[ip]
		total += c.n
		for _, p := range c.ports {
			all = append(all, net.JoinHostPort(ip, strconv.Itoa(p)))
		}
	}
	return total, listOfN(all, 3, total)
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
