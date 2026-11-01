package portcol

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/collectors/asncol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fingerprint"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A range is scanned in blocks of 256 addresses, one task each: the run
// records its progress by block, and a range of millions of addresses is
// never held as millions of seeds.
const (
	blockBits4 = 24
	blockBits6 = 120
	// maxBits6: an IPv6 range larger than this has more addresses than any
	// IPv4 range (a /8) and is no scan anyone finishes.
	maxBits6 = 104
)

// Blocks splits pf into the prefixes a range is scanned in. An IPv6 range
// of more than 2^24 addresses is refused rather than cut: nothing finishes it.
func Blocks(pf netip.Prefix) ([]netip.Prefix, error) {
	pf = pf.Masked()
	size := blockBits4
	if pf.Addr().Is6() {
		size = blockBits6
		if pf.Bits() < maxBits6 {
			return nil, fmt.Errorf("%s: an IPv6 range larger than /%d has more addresses than a /8", pf, maxBits6)
		}
	}
	if pf.Bits() >= size {
		return []netip.Prefix{pf}, nil
	}
	n := 1 << (size - pf.Bits())
	out := make([]netip.Prefix, 0, n)
	addr := pf.Addr()
	step := 1 << (pf.Addr().BitLen() - size)
	for i := 0; i < n; i++ {
		out = append(out, netip.PrefixFrom(addr, size))
		for j := 0; j < step; j++ {
			addr = addr.Next()
		}
	}
	return out, nil
}

func (c *Collector) runPrefix(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	pf, err := netip.ParsePrefix(seed.Key())
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, nil
	}
	pf = pf.Masked()
	blocks, err := Blocks(pf)
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, nil
	}
	if len(blocks) > 1 || blocks[0] != pf {
		// Too big for one task: its blocks are the work (a range met under
		// an AS number, not one the command line split).
		meta := types.RunMeta{Status: types.StatusOK}
		for _, b := range blocks {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": b.String()}})
		}
		return meta, nil
	}

	var addrs []netip.Addr
	for a := pf.Addr(); a.IsValid() && pf.Contains(a); a = a.Next() {
		addrs = append(addrs, a)
	}
	// A block a limit stopped goes on with the addresses it had not finished.
	sweep := c.Swept[pf.String()]
	swept := map[int]bool{}
	for _, n := range sweep.Done {
		swept[n] = true
	}
	finished := map[int]bool{} // the places of the addresses this run and the stopped one finished
	maps.Copy(finished, swept)
	type result struct {
		row    map[string]any
		open   []portscan.Open
		ip     string
		err    error
		follow bool // something answered: the address goes on to the other collectors
		sent   *handed
	}
	workers := c.Workers
	if workers <= 0 {
		workers = 64
	}
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		meta      = types.RunMeta{Status: types.StatusOK}
		first     error
		emitErr   error
		down, out int
		filtAddrs int
		edgeAddrs int
		udpFilt   int // open|filtered ports of addresses that answered nothing else, not listed
		udpSilent int // those addresses
		withOpen  int
		portsOut  int          // ports left out because -allow names their host with other ports only
		portsAddr int          // the addresses they were on
		asked     = len(swept) // addresses scanned wholly or in part, for a range a limit stopped
		// The closed UDP ports of addresses that have no row, and those addresses.
		udpRefused, udpRefusing int
	)
	down, out, filtAddrs, edgeAddrs = sweep.Counts["down"], sweep.Counts["outside_scope"], sweep.Counts["filtered_addresses"], sweep.Counts["cdn_addresses"]
	udpFilt, udpSilent, withOpen = sweep.Counts["udp_silent_ports"], sweep.Counts["udp_silent_addresses"], sweep.Counts["with_open"]
	portsOut, portsAddr = sweep.Counts[outScopeKey], sweep.Counts[outScopeKey+"_addresses"]
	udpRefused, udpRefusing = sweep.Counts["udp_closed_n"], sweep.Counts["udp_closed_a"]
	counts := func() map[string]any {
		return map[string]any{"with_open": withOpen, "down": down, "outside_scope": out, "filtered_addresses": filtAddrs,
			"cdn_addresses": edgeAddrs, "udp_silent_ports": udpFilt, "udp_silent_addresses": udpSilent,
			"udp_closed_n": udpRefused, "udp_closed_a": udpRefusing, outScopeKey: portsOut, outScopeKey + "_addresses": portsAddr}
	}
	// One address given is not a sweep: it is asked about, so its silent
	// UDP ports are rows. In a range, an address that answered nothing at
	// all (down, or dropping UDP) would be a screenful of them.
	single := pf.Bits() == pf.Addr().BitLen()
	sem := make(chan struct{}, workers)
	record := func(res result) {
		mu.Lock()
		defer mu.Unlock()
		if res.err != nil && first == nil {
			first = res.err
		}
		if res.row == nil {
			return
		}
		raw, _ := json.Marshal(res.row)
		_, partial := res.row[PartialKey]
		if err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: partial}); err != nil && emitErr == nil {
			emitErr = err
			return
		}
		meta.EmitCount++
		if res.follow {
			// What the address's first open port did not already hand on.
			meta.NextHints = append(meta.NextHints, res.sent.hand(ctx, append([]types.Seed{ipSeed(res.ip)}, hintsOf(res.ip, res.open)...))...)
		}
	}
	for at, a := range addrs {
		if swept[at+1] {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		stop := first != nil
		mu.Unlock()
		if stop {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(a netip.Addr, place int) {
			defer guard.Recover(ctx)
			defer wg.Done()
			defer func() { <-sem }()
			ip := a.String()
			done := func() {
				mu.Lock()
				finished[place] = true
				mu.Unlock()
			}
			if !egress.Allows(ip) {
				mu.Lock()
				out++
				finished[place] = true
				mu.Unlock()
				return
			}
			ports := c.portsOf(ip)
			edge, edgeName := false, ""
			if name, kind := fingerprint.Network(net.ParseIP(ip)); name != "" && kind != "cloud" {
				edge, edgeName = true, name
				if c.ExcludeCDN {
					ports = cdnPorts
				}
			}
			ports, outScope := inScope(ip, ip, ports)
			all := ports
			prior, resumed := c.Prior[ip]
			if resumed {
				ports = without(ports, prior.Asked)
			}
			s := &scan{up: true}
			var uerr error
			early := &earlyAddr{c: c, ctx: ctx, ip: ip}
			switch {
			case len(ports) == 0:
			case c.Discover != DiscoverOff && outScope == 0:
				if s.up, s.err = c.Scanner.Up(ctx, ip, ip); s.err == nil && s.up && c.Discover == DiscoverFirst {
					s = c.scanRange(ctx, ip, ports, early.found)
				}
			default:
				s = c.scanRange(ctx, ip, ports, early.found)
			}
			if s.err != nil {
				res := result{err: s.err}
				if stopped(s.err) {
					if s.asked > 0 {
						mu.Lock()
						asked++
						mu.Unlock()
					}
					// What it found is kept; azhaq resume asks the rest.
					if res.row = c.partialRow(ip, ip, all, ports, s, prior, resumed, edgeName, edge); res.row != nil {
						res.row["prefix"] = pf.String()
					}
				}
				record(res)
				return
			}
			mu.Lock()
			asked++
			mu.Unlock()
			if resumed {
				s, ports = withPrior(s, prior), all
			}
			var udp portscan.UDPReport
			if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
				if uports, _ := inScope(ip, ip, c.UDPPorts); len(uports) > 0 {
					udp, uerr = c.Scanner.ScanUDP(ctx, ip, ip, uports)
				}
				if uerr != nil {
					recordStops(ip, udp.Stopped)
					record(result{err: uerr})
					return
				}
			}
			// Silent ports are rows where the address showed life (a reply, a
			// refusal or an open port), or was the one asked.
			listed := len(udp.OpenFiltered) > 0 && (single || len(s.open) > 0 || len(udp.Open) > 0 || udp.Closed > 0)
			// An address that shows nothing has no row: the range's row counts
			// them. The one asked has a row for the UDP ports it refused.
			rowless := len(s.open) == 0 && len(udp.Open) == 0 && !listed && !(c.Discover == DiscoverOnly && s.up) && !(single && udp.Closed > 0)
			mu.Lock()
			switch {
			case !s.up:
				down++
			case len(s.open) > 0 || len(udp.Open) > 0:
				withOpen++
			}
			if len(s.silent) > 0 {
				filtAddrs++
			}
			if edge && c.ExcludeCDN {
				edgeAddrs++
			}
			if len(udp.OpenFiltered) > 0 && !listed {
				udpFilt += len(udp.OpenFiltered)
				udpSilent++
			}
			if rowless && udp.Closed > 0 {
				udpRefused += udp.Closed
				udpRefusing++
			}
			mu.Unlock()
			if rowless {
				if outScope > 0 { // no row of its own to say it
					mu.Lock()
					portsOut += outScope
					portsAddr++
					mu.Unlock()
				}
				done()
				return
			}
			row := c.row(ip, ip, ports, s, edgeName, edge)
			row["prefix"] = pf.String()
			if outScope > 0 {
				row[outScopeKey] = outScope
			}
			if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
				addUDP(row, udp, len(c.UDPPorts))
			}
			follow := len(s.open) > 0 || len(udp.Open) > 0
			if follow {
				// The address seed that follows finds its scan done.
				c.remember(ip, s, udp, len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly)
			}
			done()
			record(result{row: row, open: s.open, ip: ip, follow: follow, sent: &early.sent})
		}(a, at+1)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return types.RunMeta{Status: types.StatusCancelled}, err
	}
	if emitErr != nil {
		return meta, emitErr
	}
	if stopped(first) {
		// The rows of the addresses it reached are kept; this row says how
		// many that was, as the finished range's does for all of them.
		// What the block finished goes in the row, so that a resume does not ask it again.
		row := counts()
		row["range"], row["prefix"], row["addresses"], row["stopped"], row["open"] = true, pf.String(), asked, true, []int{}
		row[SweptKey] = portscan.Compact(slices.Collect(maps.Keys(finished)))
		raw, _ := json.Marshal(row)
		_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
		return types.RunMeta{Status: types.StatusCapped, EmitCount: meta.EmitCount}, first
	}
	if first != nil {
		return types.RunMeta{Status: types.StatusError, Error: first.Error()}, nil
	}
	rng := counts()
	rng["range"], rng["prefix"], rng["addresses"], rng["scanned"], rng["open"] = true, pf.String(), len(addrs)-out, len(c.portsOf("")), []int{}
	if portsOut == 0 {
		delete(rng, outScopeKey)
		delete(rng, outScopeKey+"_addresses")
	}
	raw, _ := json.Marshal(rng)
	if err := emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	meta.EmitCount++
	sort.Slice(meta.NextHints, func(i, j int) bool { return meta.NextHints[i].Key() < meta.NextHints[j].Key() })
	return meta, nil
}

// scanRange asks one address of a range its ports.
func (c *Collector) scanRange(ctx context.Context, ip string, ports []int, found func(portscan.Open)) *scan {
	r, err := c.Scanner.ScanEachFn(ctx, ip, ip, ports, found)
	return &scan{open: r.Open, silent: r.Silent, up: true, capped: r.Threshold, asked: r.Asked, err: err}
}

// earlyAddr hands one address of a range to the scheduler at its first open
// port, not when the block of 256 addresses ends: the address's own seed
// (its web, TLS and screenshot work) and each web port as it is named, so a
// sweep of minutes has web results from its first minute.
type earlyAddr struct {
	c    *Collector
	ctx  context.Context
	ip   string
	sent handed
	once sync.Once
}

func ipSeed(ip string) types.Seed {
	return types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip, "from": asncol.FromPrefix}}
}

func (e *earlyAddr) found(o portscan.Open) {
	if !catalog.Hint(e.ctx) {
		return // nothing listens: the hints come with the block's result
	}
	e.once.Do(func() {
		// Claimed first, so the seed finds the scan taken and does not start one.
		e.c.mu.Lock()
		if e.c.ranged == nil {
			e.c.ranged = map[string]bool{}
		}
		e.c.ranged[e.ip] = true
		e.c.mu.Unlock()
		e.sent.hand(e.ctx, []types.Seed{ipSeed(e.ip)})
	})
	e.sent.hand(e.ctx, hintsOf(e.ip, []portscan.Open{o}))
}

// remember keeps the scan of an address that answered, so the seed that
// follows it (a name, an address) is not scanned again.
func (c *Collector) remember(ip string, s *scan, udp portscan.UDPReport, withUDP bool) {
	done := make(chan struct{})
	close(done)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byIP[ip] = &scan{done: done, host: ip, open: s.open, silent: s.silent, up: s.up, capped: s.capped}
	if withUDP {
		if c.udpByIP == nil {
			c.udpByIP = map[string]*udpScan{}
		}
		c.udpByIP[ip] = &udpScan{done: done, rep: udp}
	}
}
