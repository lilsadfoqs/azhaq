package portcol

import (
	"cmp"
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

	leave1 := c.enterPass1() // until every address has had its first pass
	defer leave1()
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
	settled.Add(int64(len(swept)))
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
		// The addresses that answered the first pass of the default scan: their second
		// pass goes on when every address has had the first.
		later []placedJob
		// The addresses another task holds: they are waited for after every first and second pass.
		waiting []func()
		claims  []*claimRec
		phase   = 1
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
	// What the block has finished is kept as it goes, in the row a stopped block
	// leaves (what azhaq resume reads), so a kill leaves the addresses done.
	var keepFinished func()
	if len(addrs) > 1 {
		lastKept := len(swept)
		keepFinished = func() {
			mu.Lock()
			defer mu.Unlock()
			if len(finished) <= lastKept || emitErr != nil {
				return
			}
			lastKept = len(finished)
			row := counts()
			row["range"], row["prefix"], row["addresses"], row["stopped"], row["open"] = true, pf.String(), len(finished), true, []int{}
			row[SweptKey] = portscan.Compact(slices.Collect(maps.Keys(finished)))
			row[CheckpointKey] = true
			raw, _ := json.Marshal(row)
			_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
		}
		quit, ended := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(ended)
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-quit:
					return
				case <-t.C:
					keepFinished()
				}
			}
		}()
		defer func() { close(quit); <-ended }()
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
			if !egress.Allows(ip) {
				mu.Lock()
				out++
				finished[place] = true
				mu.Unlock()
				settled.Add(1)
				return
			}
			ports := c.portsOf(ip)
			edge, edgeName := false, ""
			if name, _ := fingerprint.NetworkEdge(net.ParseIP(ip)); name != "" {
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
			if !single {
				// An open port is a row as it is found, not when the block ends; a single
				// address keeps its own checkpoints (below).
				ck := c.checkpoint(func(o types.Observation) error {
					mu.Lock()
					defer mu.Unlock()
					return emit(o)
				}, ip, ip, all, prior, resumed, edgeName, edge, pf.String(), c.passOf(1))
				early.rows = func(open []portscan.Open) {
					asked := make([]int, len(open))
					for i, o := range open {
						asked[i] = o.Port
					}
					ck(portscan.Progress{Asked: asked, Open: open})
				}
			}
			// The address is asked once: when a name has it, or another range, this
			// task waits for that scan, after the first pass of every other address.
			entry, mine := c.claim(ip, ip)
			var rec *claimRec
			settle := func(*scan) {}
			if mine {
				rec = &claimRec{c: c, ip: ip, e: entry}
				mu.Lock()
				claims = append(claims, rec)
				mu.Unlock()
				settle = rec.settle
			}
			sctx := ctx
			if single {
				// One address is one long scan: it keeps what it has finished as it goes.
				sctx = portscan.WithProgress(ctx, c.checkpoint(func(o types.Observation) error {
					mu.Lock()
					defer mu.Unlock()
					return emit(o)
				}, ip, ip, all, prior, resumed, edgeName, edge, pf.String(), c.passOf(1)))
			}
			if mine {
				switch {
				case len(ports) == 0:
				case c.Discover != DiscoverOff && outScope == 0:
					if s.up, s.err = c.Scanner.Up(ctx, ip, ip); s.err == nil && s.up && c.Discover == DiscoverFirst {
						s = c.scanRange(sctx, ip, ports, early.found)
					}
				default:
					s = c.scanRange(sctx, ip, ports, early.found)
				}
				s.first = all
				if s.err != nil {
					settle(s)
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
			}
			finish := func(s *scan, ports []int) {
				defer func() { settle(s) }()
				if resumed {
					s, ports = withPrior(s, prior), all
				}
				if s.pass2 {
					ports = c.allAsked(ip, ip, all)
				}
				var udp portscan.UDPReport
				if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
					if uports, _ := inScope(ip, ip, c.UDPPorts); len(uports) > 0 {
						udp, uerr = c.scanUDPGated(ctx, ip, uports, prior.UDP)
					}
					if uerr != nil {
						recordStops(ip, udp.Stopped)
						res := result{err: uerr}
						if stopped(uerr) {
							// What it settled is kept, with how far it asked the rest.
							row := c.row(ip, ip, ports, s, edgeName, edge)
							row["prefix"] = pf.String()
							if outScope > 0 {
								row[outScopeKey] = outScope
							}
							c.udpRow(row, udp, len(c.UDPPorts))
							c.markPartial(row, ports)
							res.row = row
						}
						record(res)
						return
					}
				}
				// Silent ports are rows where the address showed life (a reply, a
				// refusal or an open port), or was the one asked.
				listed := len(udp.OpenFiltered) > 0 && (single || len(s.open) > 0 || len(udp.Open) > 0 || udp.Closed > 0)
				// An address that shows nothing has no row: the range's row counts
				// them. The one asked has a row for the UDP ports it refused.
				rowless := len(s.open) == 0 && len(udp.Open) == 0 && !listed && !(c.Discover == DiscoverOnly && s.up) && !(single && udp.Closed > 0)
				// Counted and marked finished together, after the address's row is
				// written: a checkpoint of the block (below) never names an address
				// whose row or count is missing.
				apply := func() {
					mu.Lock()
					defer mu.Unlock()
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
					if rowless && outScope > 0 { // no row of its own to say it
						portsOut += outScope
						portsAddr++
					}
					finished[place] = true
					c.settle(entry)
				}
				if rowless {
					if len(udp.OpenFiltered) > 0 {
						// The silent ports of an address that showed nothing else are
						// kept, in a row that no command prints unless asked: the
						// range's row and the summary count them.
						record(result{row: silentRow(ip, pf.String(), udp, len(c.UDPPorts))})
					}
					apply()
					return
				}
				row := c.row(ip, ip, ports, s, edgeName, edge)
				row["prefix"] = pf.String()
				if outScope > 0 {
					row[outScopeKey] = outScope
				}
				if len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly {
					c.udpRow(row, udp, len(c.UDPPorts))
				}
				follow := len(s.open) > 0 || len(udp.Open) > 0
				if follow {
					// The address seed that follows finds its scan done.
					c.remember(ip, udp, len(c.UDPPorts) > 0 && !edge && s.up && c.Discover != DiscoverOnly)
				}
				record(result{row: row, open: s.open, ip: ip, follow: follow, sent: &early.sent})
				apply()
			}
			if !mine {
				job := func() {
					select {
					case <-entry.done:
					case <-ctx.Done():
						return
					}
					s := entry
					if s.err == nil {
						s = c.topUp(sctx, ip, ip, entry, ports, early.found)
					}
					if s.err != nil {
						record(result{err: s.err})
						return
					}
					mu.Lock()
					asked++
					mu.Unlock()
					finish(s, ports)
				}
				mu.Lock()
				waiting = append(waiting, job)
				mu.Unlock()
				return
			}
			if c.escalates(ip, edge, s, prior) {
				// An address that answered goes on to the second pass, once every
				// address of the block has had the first.
				job := func() {
					c.second(ctx, func(o types.Observation) error {
						mu.Lock()
						defer mu.Unlock()
						return emit(o)
					}, ip, ip, all, ports, prior, resumed, s, edgeName, edge, pf.String(), early.found)
					if s.err != nil {
						settle(s)
						res := result{err: s.err}
						if stopped(s.err) {
							if res.row = c.partialRow(ip, ip, all, ports, s, prior, resumed, edgeName, edge); res.row != nil {
								res.row["prefix"] = pf.String()
							}
						}
						record(res)
						return
					}
					finish(s, ports)
				}
				mu.Lock()
				later = append(later, placedJob{place, job})
				mu.Unlock()
				return
			}
			finish(s, ports)
		}(a, at+1)
	}
	wg.Wait()
	leave1()
	mu.Lock()
	run2 := first == nil && ctx.Err() == nil
	mu.Unlock()
	// A claim not settled by now (a stop came first) is given up: a name
	// waiting for it is not held for good.
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range claims {
			r.settle(&scan{err: cmp.Or(first, ctx.Err(), errRangeStopped)})
		}
	}()
	if run2 && len(later)+len(waiting) > 0 {
		// The second pass goes on in address order, and only once every first pass is asked.
		c.beforePass2(ctx)
		phase = 2
		slices.SortFunc(later, func(a, b placedJob) int { return cmp.Compare(a.place, b.place) })
		jobs := make([]func(), 0, len(later)+len(waiting))
		for _, l := range later {
			jobs = append(jobs, l.job)
		}
		for _, job := range append(jobs, waiting...) {
			mu.Lock()
			stop := first != nil
			mu.Unlock()
			if stop || ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(job func()) {
				defer guard.Recover(ctx)
				defer wg.Done()
				defer func() { <-sem }()
				job()
			}(job)
		}
		wg.Wait()
	}
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
		c.markPass(row, phase, 0)
		row["addresses_of"] = len(addrs)
		raw, _ := json.Marshal(row)
		_ = emit(types.Observation{Collector: Name, Source: "tcp", Kind: "ports", Payload: raw, Confidence: 0.95, ObservedAt: time.Now().UTC(), Keep: true})
		return types.RunMeta{Status: types.StatusCapped, EmitCount: meta.EmitCount}, first
	}
	if first != nil {
		return types.RunMeta{Status: types.StatusError, Error: first.Error()}, first
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

// placedJob is the second pass of an address, by its place in its block.
type placedJob struct {
	place int
	job   func()
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

	mu    sync.Mutex
	opens []portscan.Open
	rows  func([]portscan.Open) // writes what the address has found so far, when set
}

func ipSeed(ip string) types.Seed {
	return types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip, "from": asncol.FromPrefix}}
}

func (e *earlyAddr) found(o portscan.Open) {
	if e.rows != nil {
		e.mu.Lock()
		if !slices.ContainsFunc(e.opens, func(p portscan.Open) bool { return p.Port == o.Port }) {
			e.opens = append(e.opens, o)
			e.rows(slices.Clone(e.opens)) // in order: an older list never lands after a newer
		}
		e.mu.Unlock()
	}
	e.c.reserveWeb(e.ip, e.ip, o)
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

// remember keeps the UDP scan of an address that answered, so the seed that
// follows it (a name, an address) is not scanned again; its TCP scan is the
// claim the range holds (claimRec).
func (c *Collector) remember(ip string, udp portscan.UDPReport, withUDP bool) {
	if !withUDP {
		return
	}
	done := make(chan struct{})
	close(done)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.udpByIP == nil {
		c.udpByIP = map[string]*udpScan{}
	}
	c.udpByIP[ip] = &udpScan{done: done, rep: udp}
}
