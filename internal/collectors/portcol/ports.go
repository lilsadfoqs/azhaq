// Package portcol scans the TCP ports of hosts in scope (-ports, active)
// and hands the ones that may serve HTTP to the HTTP collector.
package portcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/collectors/asncol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/httpcol"
	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

const Name = "azhaq-ports"

// cdnPorts are the only ports scanned on a CDN or WAF address when the
// scan is told to exclude them (-ec): naabu's 80 and 443, and 8080 and 8443.
// By default the address is scanned in full, as naabu does.
var cdnPorts = []int{80, 443, 8080, 8443}

// Discovery is how a scan tells which addresses are up before it asks
// their ports.
type Discovery int

const (
	// DiscoverOff scans every address, as naabu does.
	DiscoverOff Discovery = iota
	// DiscoverFirst scans only the addresses that answered a connect to
	// 80 or 443 (-wn).
	DiscoverFirst
	// DiscoverOnly lists those addresses and scans nothing (-sn).
	DiscoverOnly
)

type Collector struct {
	// Prior holds, by address, what a scan a limit stopped found and asked.
	Prior   map[string]Prior
	Pool    *dnsr.Pool
	Scanner *portscan.Scanner
	Ports   []int
	// UDPPorts are the UDP ports to ask on each address; none, no UDP scan.
	UDPPorts []int
	// IPv6 says whether this machine can reach IPv6 addresses; nil is
	// egress.IPv6Routable.
	IPv6 func() bool
	// ExcludeCDN limits a CDN or WAF address to its web ports; by default it
	// is scanned in full.
	ExcludeCDN bool
	// Discover is how addresses are told up before they are scanned.
	Discover Discovery
	// IPv4Only and IPv6Only keep a name to one family; AllIPs scans every
	// address of a name, not the first two of each family.
	IPv4Only, IPv6Only, AllIPs bool
	// PortsFor gives an address or name ports of its own (host:port given
	// without -p); its key is the host as written, lower case.
	PortsFor map[string][]int
	// Workers is how many addresses of a range are asked at once; 0 is 64.
	Workers int
	// WebCost is how many requests the budget keeps for mapping each web
	// service the scan finds open (egress.Reserve); zero keeps none.
	WebCost int

	mu    sync.Mutex
	byIP  map[string]*scan // one scan per address, however many names point to it
	maxIP int              // addresses scanned per name

	udpByIP map[string]*udpScan
	udpGate chan struct{}   // the addresses whose UDP ports are being asked
	ranged  map[string]bool // addresses a range scan handed on as it found them
	held    map[string]bool // endpoints whose web mapping the budget has a reserve for

	// Swept holds, by prefix, the blocks a limit stopped: the addresses of
	// those the run had finished are not asked again (azhaq resume).
	Swept   map[string]Sweep
	sweptIP map[string]bool
}

type scan struct {
	done     chan struct{}
	host     string // the name the services were asked under
	open     []portscan.Open
	silent   []int
	unprobed int  // open ports left without the protocol probes
	up       bool // answered discovery, or discovery was off
	capped   bool // the threshold of open ports stopped it
	asked    int  // ports asked, in the scanner's order, before it stopped
	err      error
}

func New(pool *dnsr.Pool, ports []int, rate float64) *Collector {
	c := &Collector{Pool: pool, Ports: ports, Scanner: &portscan.Scanner{Rate: rate, Take: egress.TakeSweep, UserAgent: fetch.UserAgent},
		byIP: map[string]*scan{}, maxIP: 2}
	c.Scanner.Opened = c.holdWeb
	return c
}

// holdWeb sets aside the requests that mapping a web service needs
// (egress.Reserve) the moment a port accepts a connection, once for each
// address and port: a sweep that would spend the whole budget leaves them,
// though the port is not yet named. A port that proves no web service gives
// them back (reserveWeb).
func (c *Collector) holdWeb(ip string, port int) {
	if c.WebCost <= 0 {
		return
	}
	key := net.JoinHostPort(ip, strconv.Itoa(port))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held == nil {
		c.held = map[string]bool{}
	}
	if !c.held[key] {
		c.held[key] = true
		egress.Reserve(int64(c.WebCost))
	}
}

// reserveWeb keeps the reserve of a port named a web service, and gives back
// that of any other: its one probe is paid from the budget as any request is.
func (c *Collector) reserveWeb(ip string, o portscan.Open) {
	if c.WebCost <= 0 {
		return
	}
	if svc := strings.TrimSuffix(o.Service, "?"); svc == "http" || svc == "https" {
		return
	}
	key := net.JoinHostPort(ip, strconv.Itoa(o.Port))
	c.mu.Lock()
	held := c.held[key]
	c.held[key] = false
	c.mu.Unlock()
	if held {
		egress.Reserve(-int64(c.WebCost))
	}
}

func (c *Collector) routable() bool {
	if c.IPv6 != nil {
		return c.IPv6()
	}
	return egress.IPv6Routable()
}

func (c *Collector) Name() string { return Name }

// Info: connects to every listed port of the target; needs -ports and
// -allow, and waits for DNS so dead names are not scanned.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "ports", After: "azhaq-dns"}
}

// Skip: the seed of an address a range scan has handed on is that scan's own,
// its row and its web ports already given; running it would only wait for
// the address to be scanned through.
func (c *Collector) Skip(seed types.Seed) bool {
	if seed.Type != types.TypeIPAddress || seed.Keys["from"] != asncol.FromPrefix {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ip := normalize.Hostname(seed.Key())
	return c.ranged[ip] || c.sweptIP[ip]
}

func (c *Collector) Inputs() []types.SeedType {
	return []types.SeedType{types.TypeHostname, types.TypeIPAddress, types.TypePrefix}
}

func (c *Collector) Outputs() []string { return []string{"ports"} }

func (c *Collector) portsOf(host string) []int {
	if p, ok := c.PortsFor[host]; ok {
		return p
	}
	return c.Ports
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	if seed.Type == types.TypePrefix {
		return c.runPrefix(ctx, seed, emit)
	}
	host := normalize.Hostname(seed.Key())
	var ips []string
	// A name behind a CDN or WAF answers on the provider's shared edges
	// (-ec limits it to their web ports). Any of its addresses or its
	// CNAME says so for all of them (CloudFront's IPv6 ranges read as
	// plain AWS).
	edgeName := ""
	var unrouted []string // IPv6 addresses this machine cannot reach
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{ip.String()}
	} else if c.Pool != nil {
		var answer dnsr.Answer
		if c.IPv4Only {
			answer = c.Pool.Resolve(ctx, host)
		} else {
			answer = c.Pool.ResolveBoth(ctx, host)
		}
		if name, kind := fingerprint.NetworkByName(answer.CNAME...); name != "" && kind != "cloud" {
			edgeName = name
		}
		// Both families: a service may listen on one only (naabu -iv 4,6).
		// IPv6 only where this machine can reach it; the summary says
		// when it cannot.
		limit := c.maxIP
		if c.AllIPs {
			limit = 1 << 20
		}
		v4, v6 := 0, 0
		for _, ip := range answer.IPs() {
			switch {
			case net.ParseIP(ip).To4() != nil:
				if v4 < limit && !c.IPv6Only {
					v4++
					ips = append(ips, ip)
				}
			case c.IPv4Only:
			case !c.routable():
				unrouted = append(unrouted, ip)
			case v6 < limit:
				v6++
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 && len(unrouted) == 0 {
			// Nothing to connect to: no such name, a resolver that did not
			// answer, or no address of the family asked for.
			why := answer.Status
			if answer.Live() {
				why = "no address of the family asked for"
			}
			raw, _ := json.Marshal(map[string]any{"host": host, "scanned": 0, "open": []int{}, "unresolved": why})
			err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()})
			meta := types.RunMeta{Status: types.StatusOK, EmitCount: 1}
			if answer.Status == dnsr.StatusFailed || answer.Status == dnsr.StatusBroken {
				meta.Status, meta.Error = types.StatusError, "no answer from the DNS resolvers: "+answer.Err
			}
			return meta, err
		}
	}
	if len(ips) == 0 && len(unrouted) > 0 {
		// An IPv6-only name: nothing scanned, and the row says why.
		raw, _ := json.Marshal(map[string]any{"host": host, "scanned": 0, "open": []int{}, unroutedKey: unrouted})
		err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()})
		return types.RunMeta{Status: types.StatusOK, EmitCount: 1}, err
	}
	for _, ip := range ips {
		if name, _ := fingerprint.NetworkEdge(net.ParseIP(ip)); name != "" && edgeName == "" {
			edgeName = name
		}
	}
	meta := types.RunMeta{Status: types.StatusOK}
	var sent handed
	found := func(o portscan.Open) {
		if catalog.Hint(ctx) {
			sent.hand(ctx, hintsOf(host, []portscan.Open{o}))
		}
	}
	for _, ip := range ips {
		found := func(o portscan.Open) {
			c.reserveWeb(ip, o)
			found(o)
		}
		ports := c.portsOf(host)
		name := edgeName
		edge := name != ""
		if edge && c.ExcludeCDN {
			ports = cdnPorts
		}
		ports, outScope := inScope(host, ip, ports)
		// A scan an earlier run stopped asks only the ports it had not.
		all := ports
		prior, resumed := c.Prior[ip]
		if resumed {
			ports = without(ports, prior.Asked)
		}
		var s *scan
		var err error
		sctx := portscan.WithProgress(ctx, c.checkpoint(emit, host, ip, all, prior, resumed, name, edge, ""))
		switch {
		case len(ports) == 0:
			s = &scan{up: true} // every port is outside the scope: nothing to ask
		case c.Discover == DiscoverOff || outScope > 0:
			// A host held to some ports is asked those, with no discovery
			// of its own: its 80 and 443 may be outside the scope.
			s, err = c.scanOnce(sctx, host, ip, ports, found)
		default:
			s, err = c.discoverOnce(sctx, host, ip, ports, found)
		}
		if err != nil && ctx.Err() != nil {
			return types.RunMeta{Status: types.StatusCancelled}, err
		}
		if stopped(err) {
			// Stopped by -max-requests or the kill file: what it found is
			// kept, with the ports it asked, and azhaq resume asks the rest.
			c.forget(ip)
			if row := c.partialRow(host, ip, all, ports, s, prior, resumed, name, edge); row != nil {
				raw, _ := json.Marshal(row)
				_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
			}
			return types.RunMeta{Status: types.StatusCapped}, err
		}
		if resumed {
			s, ports = withPrior(s, prior), all
		}
		var udp portscan.UDPReport
		if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
			var uerr error
			if udp, uerr = c.scanUDPOnce(ctx, host, ip); uerr != nil {
				if ctx.Err() != nil {
					return types.RunMeta{Status: types.StatusCancelled}, uerr
				}
				if stopped(uerr) {
					// What the UDP scan found and asked is kept; azhaq resume asks the rest.
					c.forget(ip)
					row := c.row(host, ip, ports, s, name, edge)
					c.udpRow(row, udp, len(c.UDPPorts))
					c.markPartial(row, ports)
					raw, _ := json.Marshal(row)
					_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
					return types.RunMeta{Status: types.StatusCapped}, uerr
				}
			}
		}
		row := c.row(host, ip, ports, s, name, edge)
		if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
			c.udpRow(row, udp, len(c.UDPPorts))
		}
		if s.unprobed > 0 {
			row["unprobed"] = s.unprobed
		}
		if outScope > 0 {
			row[outScopeKey] = outScope
		}
		if len(unrouted) > 0 {
			row[unroutedKey] = unrouted
		}
		raw, _ := json.Marshal(row)
		if err := emit(types.Observation{
			Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(),
		}); err != nil {
			return meta, err
		}
		meta.EmitCount++
		meta.NextHints = append(meta.NextHints, sent.hand(ctx, hintsOf(host, s.open))...)
	}
	return meta, nil
}

// row is an address's row: what was asked of it, what answered and what did
// not.
func (c *Collector) row(host, ip string, ports []int, s *scan, edge string, isEdge bool) map[string]any {
	row := map[string]any{"host": host, "ip": ip, "scanned": len(ports), "open": portsOf(s.open)}
	switch {
	case c.Discover != DiscoverOff:
		row["up"] = s.up
		if !s.up || c.Discover == DiscoverOnly {
			row["scanned"] = 0
		}
	}
	if len(s.open) > 0 {
		row["services"] = s.open
	}
	if len(s.silent) > 0 {
		row["filtered"] = len(s.silent)
		if len(s.silent) <= maxListed {
			row["filtered_ports"] = s.silent
		}
	}
	if s.capped {
		row["threshold"] = true
	}
	if isEdge {
		row["cdn"] = edge
		if c.ExcludeCDN {
			row["note"] = "CDN or WAF address: web ports only"
		} else {
			row["note"] = "CDN or WAF address: scanned in full"
		}
	}
	return row
}

// hintsOf are the web ports a name's scan found, as URLs for the HTTP
// collector.
func hintsOf(host string, open []portscan.Open) []types.Seed {
	var out []types.Seed
	for _, o := range open {
		if !o.Web() || o.Port == 80 || o.Port == 443 {
			continue // the HTTP collector tries 80 and 443 on every name
		}
		hp := net.JoinHostPort(host, strconv.Itoa(o.Port))
		keys := map[string]string{"url": "https://" + hp + "/", httpcol.FallbackKey: "http"}
		switch {
		case o.Service == "http" || o.Service == "https": // the probe found out which
			keys = map[string]string{"url": o.Service + "://" + hp + "/"}
		case o.Service == "" && httpcol.HTTPFirst(o.Port):
			// Not probed: plain HTTP first, as httpx does. A web port there is
			// mostly plain, so the first request answers; a TLS port answers 400
			// and is asked again over TLS.
			keys = map[string]string{"url": "http://" + hp + "/", httpcol.FallbackKey: "https"}
		}
		keys[types.SameTargetKey] = "1" // a port of the target itself, not a step away from it
		if !namedWeb(o.Service) {
			keys[types.UnnamedPortKey] = "1" // a close on the request is an answer: it is not a web service
		}
		out = append(out, types.Seed{Type: types.TypeURL, Keys: keys})
	}
	return out
}

// namedWeb says the scan named the port as an HTTP service from what it
// answered (a name guessed from the port number ends in "?").
func namedWeb(service string) bool {
	switch service {
	case "http", "https", "elasticsearch", "docker", "kubernetes", "http-proxy":
		return true
	}
	return false
}

// handed is the seeds a scan has given the scheduler, each once.
type handed struct {
	mu   sync.Mutex
	seen map[string]bool
}

// hand gives the scheduler the seeds it has not had yet while the scan is
// still running, so a web port found early is probed at once, not when the
// sweep ends. Without a scheduler listening they come back, for RunMeta.NextHints.
func (h *handed) hand(ctx context.Context, seeds []types.Seed) []types.Seed {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil {
		h.seen = map[string]bool{}
	}
	var fresh []types.Seed
	for _, s := range seeds {
		if k := string(s.Type) + "\x00" + s.Key(); !h.seen[k] {
			h.seen[k] = true
			fresh = append(fresh, s)
		}
	}
	if len(fresh) == 0 || catalog.Hint(ctx, fresh...) {
		return nil
	}
	return fresh
}

// outScopeKey is how many ports of an address a row left out because -allow
// names its host with another port only.
const outScopeKey = "ports_outside_scope"

// inScope keeps the ports the scope allows for an address, or for the name it
// was found under: -allow HOST:PORT allows that port only. n is how many it
// left out.
func inScope(host, ip string, ports []int) (kept []int, n int) {
	if !egress.HasScope() {
		return ports, 0
	}
	kept = make([]int, 0, len(ports))
	for _, p := range ports {
		ps := strconv.Itoa(p)
		if egress.AllowsAddr(ip, ps) || host != "" && host != ip && egress.AllowsAddr(host, ps) {
			kept = append(kept, p)
		}
	}
	return kept, len(ports) - len(kept)
}

// cmpWho is the address a row is about, else its name.
func cmpWho(host, ip string) string {
	if ip != "" && ip != host {
		return ip
	}
	return host
}

// unroutedKey lists, in a name's rows, its IPv6 addresses this machine
// has no route to, which were not scanned.
const unroutedKey = "ipv6_not_scanned"

// Notes are what a run's port scans leave for its summary: names that did
// not resolve, IPv6 addresses this machine could not scan, ports that did
// not answer, addresses left out and why.
func Notes(obs []types.StoredObservation) []string {
	names := map[string]bool{}
	var silent []string // address: ports, where a few ports answered neither way, twice
	var udp udpSummary
	var unprobed []string // address: open ports left without the protocol probes
	var unresolved []string
	var stopped []string // addresses the open-port threshold stopped
	var edges []string
	var down, outside, filtAddrs, addrs, ranges int
	var portsOut, portsOutAddrs int // ports left out of the scope's port, and the addresses they were on
	var portsOutAt []string
	portsOutSeen := map[string]bool{} // an address's ports are counted once, whether its range or its own seed scanned it
	// A row of a scan a limit stopped is read only while nothing came
	// after it: the row that finishes the scan says it all.
	newest := map[string]int{}
	lastRange := map[string]int{} // by prefix: the stopped block's row counts until the one after it
	for i, o := range obs {
		if o.Collector == Name {
			var id struct {
				Host   string `json:"host"`
				IP     string `json:"ip"`
				Range  bool   `json:"range"`
				Prefix string `json:"prefix"`
			}
			if json.Unmarshal(o.Payload, &id) == nil {
				newest[id.Host+"\x00"+id.IP] = i
				if id.Range {
					lastRange[id.Prefix] = i
				}
			}
		}
	}
	for i, o := range obs {
		if o.Collector != Name {
			continue
		}
		var p struct {
			Partial    bool              `json:"partial"`
			Host       string            `json:"host"`
			IP         string            `json:"ip"`
			Unrouted   []string          `json:"ipv6_not_scanned"`
			Filtered   []int             `json:"filtered_ports"`
			UDPFilt    []int             `json:"udp_open_filtered"`
			UDPUnlist  int               `json:"udp_unlisted"`
			UDPClosed  int               `json:"udp_closed"`
			ClosedAt   []int             `json:"udp_closed_ports"`
			ClosedN    int               `json:"udp_closed_n"`
			ClosedA    int               `json:"udp_closed_a"`
			UDPSilentN int               `json:"udp_silent_ports"`
			UDPSilentA int               `json:"udp_silent_addresses"`
			Unresolved string            `json:"unresolved"`
			Threshold  bool              `json:"threshold"`
			CDN        string            `json:"cdn"`
			Note       string            `json:"note"`
			Up         *bool             `json:"up"`
			Range      bool              `json:"range"`
			Stopped    bool              `json:"stopped"`
			Prefix     string            `json:"prefix"`
			Addresses  int               `json:"addresses"`
			Down       int               `json:"down"`
			Outside    int               `json:"outside_scope"`
			FiltAddrs  int               `json:"filtered_addresses"`
			Edges      int               `json:"cdn_addresses"`
			UDPLimit   int               `json:"udp_limited"`
			UDPAsked   map[string]string `json:"udp_asked"`
			UDPOnce    bool              `json:"udp_one_request"`
			Unprobed   int               `json:"unprobed"`
			PortsOut   int               `json:"ports_outside_scope"`
			PortsOutA  int               `json:"ports_outside_scope_addresses"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Partial && newest[p.Host+"\x00"+p.IP] != i {
			continue
		}
		if p.Range && p.Stopped && lastRange[p.Prefix] != i {
			continue
		}
		if p.Range {
			ranges++
			addrs += p.Addresses
			down += p.Down
			outside += p.Outside
			filtAddrs += p.FiltAddrs
			if p.Edges > 0 {
				edges = append(edges, fmt.Sprintf("%d addresses of a range", p.Edges))
			}
			udp.silentN += p.UDPSilentN
			udp.silentIPs += p.UDPSilentA
			udp.closedN += p.ClosedN
			udp.closedIPs += p.ClosedA
			portsOut += p.PortsOut
			portsOutAddrs += p.PortsOutA
			continue
		}
		if who := cmpWho(p.Host, p.IP); p.PortsOut > 0 && !portsOutSeen[who] {
			portsOutSeen[who] = true
			portsOut += p.PortsOut
			portsOutAddrs++
			portsOutAt = append(portsOutAt, who)
		}
		if p.Unresolved != "" {
			unresolved = append(unresolved, p.Host)
		}
		if p.Up != nil && !*p.Up {
			down++
		}
		if p.Threshold {
			stopped = append(stopped, p.IP)
		}
		if p.CDN != "" && p.Prefix == "" && strings.Contains(p.Note, "web ports only") {
			edges = append(edges, p.IP+" ("+p.CDN+")")
		}
		if len(p.Unrouted) > 0 {
			names[p.Host] = true
		}
		who := p.IP
		if who == "" {
			who = p.Host
		}
		filt := p.UDPFilt
		if p.Partial && len(p.UDPAsked) > 0 {
			// Ports asked only some of their requests are not decided: the
			// stop notes name them, and this note is for the ones that are.
			un := udpPrior(nil, "", p.UDPAsked, nil).Asked
			filt = nil
			for _, port := range p.UDPFilt {
				if _, open := un[port]; !open {
					filt = append(filt, port)
				}
			}
		}
		udp.add(who, filt, p.UDPUnlist, p.UDPLimit)
		udp.once = udp.once || p.UDPOnce
		udp.addClosed(who, p.UDPClosed, p.ClosedAt)
		if p.Unprobed > 0 {
			unprobed = append(unprobed, fmt.Sprintf("%s: %d", p.IP, p.Unprobed))
		}
		if len(p.Filtered) > 0 {
			where := p.Host
			if p.IP != "" && p.IP != p.Host {
				where += " (" + p.IP + ")"
			}
			silent = append(silent, where+" "+portList(p.Filtered, 8))
		}
	}
	var out []string
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		out = append(out, fmt.Sprintf("%d names did not resolve and were not scanned: %s", len(unresolved), listOf(unresolved, 5)))
	}
	switch len(names) {
	case 0:
	case 1:
		out = append(out, "IPv6 addresses of 1 name not scanned: no IPv6 route from this machine")
	default:
		out = append(out, fmt.Sprintf("IPv6 addresses of %d names not scanned: no IPv6 route from this machine", len(names)))
	}
	if outside > 0 {
		out = append(out, fmt.Sprintf("%d addresses in the ranges are outside the scope (-deny, -allow) and were not scanned", outside))
	}
	if portsOut > 0 {
		sort.Strings(portsOutAt)
		at := ""
		if len(portsOutAt) > 0 {
			at = ": " + listOf(portsOutAt, 3)
		}
		out = append(out, fmt.Sprintf("%d ports on %d addresses were not scanned: -allow lists their hosts with other ports only (HOST:PORT allows that port; HOST alone allows every port)%s", portsOut, portsOutAddrs, at))
	}
	if down > 0 {
		out = append(out, fmt.Sprintf("%d addresses answered neither a connect to 80 nor to 443 (asked twice) and were not scanned: a host that drops both is not found this way, scan without -wn to ask it anyway", down))
	}
	if len(edges) > 0 {
		out = append(out, fmt.Sprintf("CDN or WAF addresses were asked only on ports 80, 443, 8080 and 8443, as -ec says (%s): drop -ec to scan them in full", listOf(edges, 3)))
	}
	if len(stopped) > 0 {
		out = append(out, fmt.Sprintf("reached the open-port threshold (-pts): ports not yet asked were left out, and open ports past it may be missing: %s", listOf(stopped, 3)))
	}
	if filtAddrs > 0 {
		out = append(out, fmt.Sprintf("%d addresses in the ranges had ports that neither accepted nor refused a connect, asked twice: dead, or filtered; they are not listed one by one", filtAddrs))
	}
	if len(silent) > 0 {
		sort.Strings(silent)
		more := ""
		if len(silent) > 3 {
			more = fmt.Sprintf(" and %d more addresses", len(silent)-3)
			silent = silent[:3]
		}
		out = append(out, fmt.Sprintf("ports that neither accepted nor refused a connect, asked twice: %s%s; filtered, or the host drops connects: scan them again to be sure (azhaq show -db FILE HOST lists them all)",
			strings.Join(silent, "; "), more))
	}
	if len(unprobed) > 0 {
		sort.Strings(unprobed)
		out = append(out, "open ports whose protocol was not probed, after several others on the same address could not be named (a firewall or tarpit that accepts every connect): "+strings.Join(unprobed, "; "))
	}
	return append(out, udp.notes()...)
}

// listOf is up to n of items, then how many more.
func listOf(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
}

// listOfN is up to n of items, then how many more of total there are (the
// items may be fewer than total).
func listOfN(items []string, n, total int) string {
	if len(items) > n {
		items = items[:n]
	}
	if more := total - len(items); more > 0 {
		return fmt.Sprintf("%s and %d more", strings.Join(items, ", "), more)
	}
	return strings.Join(items, ", ")
}

// portList is "80, 443" with at most n ports, then how many more.
func portList(ports []int, n int) string {
	var parts []string
	for i, p := range ports {
		if i == n {
			parts = append(parts, fmt.Sprintf("+%d more", len(ports)-n))
			break
		}
		parts = append(parts, strconv.Itoa(p))
	}
	if len(ports) == 1 {
		return "port " + parts[0]
	}
	return "ports " + strings.Join(parts, ", ")
}

// maxListed: a row lists the ports that did not answer when there are
// no more than this; past it, a firewall drops them and the count says
// enough.
const maxListed = 64

// scanOnce asks an address's ports, once however many names point to it.
func (c *Collector) scanOnce(ctx context.Context, host, ip string, ports []int, found func(portscan.Open)) (*scan, error) {
	return c.once(ctx, host, ip, func() *scan {
		r, err := c.Scanner.ScanEachFn(ctx, host, ip, ports, found)
		return &scan{open: r.Open, silent: r.Silent, unprobed: r.Unprobed, up: true, capped: r.Threshold, asked: r.Asked, err: err}
	}, func(s *scan) (*scan, error) {
		open, err := c.askAgain(ctx, host, ip, s.open)
		return &scan{open: open, silent: s.silent, unprobed: s.unprobed, up: s.up, capped: s.capped}, err
	})
}

// discoverOnce is scanOnce for a scan that first asks whether the address
// is up, and stops there when told to (-sn).
func (c *Collector) discoverOnce(ctx context.Context, host, ip string, ports []int, found func(portscan.Open)) (*scan, error) {
	return c.once(ctx, host, ip, func() *scan {
		up, err := c.Scanner.Up(ctx, host, ip)
		if err != nil || !up || c.Discover == DiscoverOnly {
			return &scan{up: up, err: err}
		}
		r, err := c.Scanner.ScanEachFn(ctx, host, ip, ports, found)
		return &scan{open: r.Open, silent: r.Silent, unprobed: r.Unprobed, up: true, capped: r.Threshold, err: err}
	}, func(s *scan) (*scan, error) {
		if !s.up || c.Discover == DiscoverOnly {
			return s, nil
		}
		open, err := c.askAgain(ctx, host, ip, s.open)
		return &scan{open: open, silent: s.silent, unprobed: s.unprobed, up: s.up, capped: s.capped}, err
	})
}

// once runs scan for an address the first time it is asked for and shares
// the answer; another name on it gets again, which asks its web ports
// under that name.
func (c *Collector) once(ctx context.Context, host, ip string, run func() *scan, again func(*scan) (*scan, error)) (*scan, error) {
	c.mu.Lock()
	s, ok := c.byIP[ip]
	if !ok {
		s = &scan{done: make(chan struct{}), host: host}
		c.byIP[ip] = s
	}
	c.mu.Unlock()
	if ok {
		select {
		case <-s.done:
		case <-ctx.Done():
			return &scan{}, ctx.Err()
		}
		if s.err != nil || s.host == host {
			return s, s.err
		}
		return again(s)
	}
	r := run()
	s.open, s.silent, s.unprobed, s.up, s.capped, s.asked, s.err = r.open, r.silent, r.unprobed, r.up, r.capped, r.asked, r.err
	close(s.done)
	return s, s.err
}

// askAgain is an address's open ports for another name on it: the
// connects are not repeated, but a web or TLS port is asked again under
// this name (its Host header and SNI), whose site and certificate may be
// its own.
func (c *Collector) askAgain(ctx context.Context, host, ip string, open []portscan.Open) ([]portscan.Open, error) {
	var web []int
	for _, o := range open {
		switch strings.TrimSuffix(o.Service, "?") {
		case "http", "https", "tls":
			web = append(web, o.Port)
		}
	}
	out := append([]portscan.Open(nil), open...)
	if len(web) == 0 {
		return out, nil
	}
	again, err := c.Scanner.Scan(ctx, host, ip, web)
	byPort := map[int]portscan.Open{}
	for _, o := range again {
		byPort[o.Port] = o
	}
	for i, o := range out {
		if n, ok := byPort[o.Port]; ok {
			out[i] = n
		}
	}
	return out, err
}

// forget drops an address's scan so a resumed run scans it again.
func (c *Collector) forget(ip string) {
	c.mu.Lock()
	delete(c.byIP, ip)
	delete(c.udpByIP, ip)
	c.mu.Unlock()
}

func portsOf(open []portscan.Open) []int {
	out := make([]int, 0, len(open))
	for _, o := range open {
		out = append(out, o.Port)
	}
	return out
}

// PartialKey marks the row of a scan a limit stopped; AskedKey lists the
// ports it asked (1-1000,8080), which azhaq resume does not ask again.
const (
	PartialKey = "partial"
	AskedKey   = "asked_ports"
)

// SweptKey is the place, in its block, of each address a stopped range scan
// finished (1-200,203), which azhaq resume does not ask again.
const SweptKey = "swept"

// Sweep is what a stopped scan of a block of addresses had finished: the
// places of the addresses, and the counts its row kept.
type Sweep struct {
	Done   []int
	Counts map[string]int
}

// Swept reads, from the rows a run wrote since it began, the blocks a limit
// stopped, by prefix. A block whose scan ended after is not among them.
func Swept(obs []types.StoredObservation, since time.Time) map[string]Sweep {
	out := map[string]Sweep{}
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "ports" || o.ObservedAt.Before(since) {
			continue
		}
		var row map[string]any
		if json.Unmarshal(o.Payload, &row) != nil || row["range"] != true {
			continue
		}
		prefix, _ := row["prefix"].(string)
		if row["stopped"] != true {
			delete(out, prefix)
			continue
		}
		spec, _ := row[SweptKey].(string)
		done, err := places(spec)
		if prefix == "" || err != nil {
			continue
		}
		counts := map[string]int{}
		for k, v := range row {
			if n, ok := v.(float64); ok {
				counts[k] = int(n)
			}
		}
		out[prefix] = Sweep{Done: done, Counts: counts}
	}
	return out
}

// places reads a list a row kept (portscan.Compact): an empty one is none, not
// the default port list portscan.Ports reads it as.
func places(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	return portscan.Ports(spec)
}

// sweptAddrs are the addresses of the blocks a limit stopped that the run
// had finished.
func sweptAddrs(swept map[string]Sweep) map[string]bool {
	out := map[string]bool{}
	for prefix, sw := range swept {
		pf, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		pf = pf.Masked()
		done := map[int]bool{}
		for _, n := range sw.Done {
			done[n] = true
		}
		n := 1
		for a := pf.Addr(); a.IsValid() && pf.Contains(a); a = a.Next() {
			if done[n] {
				out[a.String()] = true
			}
			n++
		}
	}
	return out
}

// Prior is what a stopped scan of an address found and asked.
type Prior struct {
	Asked []int
	Open  []portscan.Open
	UDP   portscan.UDPPrior
}

// Priors reads the rows of scans a limit stopped from a workspace: the
// newest for each address.
func Priors(obs []types.StoredObservation) map[string]Prior {
	out := map[string]Prior{}
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "ports" {
			continue
		}
		var row struct {
			IP       string             `json:"ip"`
			Partial  bool               `json:"partial"`
			Asked    string             `json:"asked_ports"`
			Services []portscan.Open    `json:"services"`
			UDP      []portscan.UDPPort `json:"udp_services"`
			Refused  string             `json:"udp_refused"`
			UDPAsked map[string]string  `json:"udp_asked"`
			UDPFilt  []int              `json:"udp_open_filtered"`
		}
		if json.Unmarshal(o.Payload, &row) != nil || row.IP == "" {
			continue
		}
		if !row.Partial {
			delete(out, row.IP) // a whole scan came after it
			continue
		}
		asked, err := places(row.Asked)
		if err != nil {
			continue
		}
		out[row.IP] = Prior{Asked: asked, Open: row.Services, UDP: udpPrior(row.UDP, row.Refused, row.UDPAsked, row.UDPFilt)}
	}
	return out
}

func without(ports, asked []int) []int {
	done := map[int]bool{}
	for _, p := range asked {
		done[p] = true
	}
	var out []int
	for _, p := range ports {
		if !done[p] {
			out = append(out, p)
		}
	}
	return out
}

// stopped: a limit ended the scan, not a failure.
func stopped(err error) bool {
	return errors.Is(err, neterr.ErrBudget) || errors.Is(err, neterr.ErrKilled)
}

// partialRow is the row of a scan a limit stopped: the ports it found and
// the ones it asked, with what an earlier stopped run of it had.
func (c *Collector) partialRow(host, ip string, all, ports []int, s *scan, prior Prior, resumed bool, name string, edge bool) map[string]any {
	if s == nil || (s.asked == 0 && !resumed) {
		return nil
	}
	return c.partialRowOf(host, ip, all, c.Scanner.Ordered(ip, ports)[:min(s.asked, len(ports))], s, prior, resumed, name, edge)
}

// partialRowOf is partialRow for the ports named as asked.
func (c *Collector) partialRowOf(host, ip string, all, asked []int, s *scan, prior Prior, resumed bool, name string, edge bool) map[string]any {
	part := s
	if resumed {
		part = withPrior(s, prior)
		asked = append(slices.Clone(prior.Asked), asked...)
	}
	row := c.row(host, ip, all, part, name, edge)
	row["scanned"] = len(asked)
	row[PartialKey] = true
	row[AskedKey] = portscan.Compact(asked)
	return row
}

// CheckpointKey marks the partial row a scan keeps while it goes, as against
// the one a limit leaves: azhaq resume asks what neither names.
const CheckpointKey = "checkpoint"

// checkpoint keeps what the scan of an address has finished, so that a run
// killed with no chance to say so is resumed after those ports. The row is
// the stopped scan's, kept at once (Keep) and not held to the end of the task.
func (c *Collector) checkpoint(emit func(types.Observation) error, host, ip string, all []int, prior Prior, resumed bool, name string, edge bool, prefix string) func(portscan.Progress) {
	return func(p portscan.Progress) {
		row := c.partialRowOf(host, ip, all, p.Asked, &scan{open: p.Open, up: true}, prior, resumed, name, edge)
		row[CheckpointKey] = true
		if prefix != "" {
			row["prefix"] = prefix // the single address of a block
		}
		raw, _ := json.Marshal(row)
		_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
	}
}

// markPartial marks the row of a scan whose UDP part a limit stopped: every
// TCP port of it was asked.
func (c *Collector) markPartial(row map[string]any, tcp []int) {
	row[PartialKey] = true
	row[AskedKey] = portscan.Compact(tcp)
}

// withPrior is s with the open ports an earlier stopped scan found.
func withPrior(s *scan, prior Prior) *scan {
	m := *s
	m.open = append(slices.Clone(prior.Open), s.open...)
	sort.Slice(m.open, func(i, j int) bool { return m.open[i].Port < m.open[j].Port })
	return &m
}
