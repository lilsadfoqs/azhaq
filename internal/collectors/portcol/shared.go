package portcol

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"sync"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// An address is asked its ports once, whether it is a member of a range, a
// name's address or both: the first task to reach it claims it, and the
// others wait for its scan and ask only the ports it did not (topUp).

var closedCh = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// quietBlock remembers, for a block of 256 addresses, the ones a range asked
// that had no port open: no scan is kept for them, a bit says they were asked
// and whether they were up.
type quietBlock struct{ asked, up [4]uint64 }

func quietKey(a netip.Addr) (netip.Prefix, uint8) {
	bits := 24
	if a.Is6() {
		bits = 120
	}
	b := a.AsSlice()
	return netip.PrefixFrom(a, bits).Masked(), b[len(b)-1]
}

// markQuiet records that a range asked ip and found no port open on it.
// c.mu is held.
func (c *Collector) markQuiet(ip string, up bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	if c.quiet == nil {
		c.quiet = map[netip.Prefix]*quietBlock{}
	}
	k, i := quietKey(a.Unmap())
	q := c.quiet[k]
	if q == nil {
		q = &quietBlock{}
		c.quiet[k] = q
	}
	q.asked[i/64] |= 1 << (i % 64)
	if up {
		q.up[i/64] |= 1 << (i % 64)
	}
}

// quietScan is the scan of an address a range asked and found nothing open
// on, or nil. c.mu is held.
func (c *Collector) quietScan(ip string) *scan {
	a, err := netip.ParseAddr(ip)
	if err != nil || c.quiet == nil {
		return nil
	}
	k, i := quietKey(a.Unmap())
	q := c.quiet[k]
	if q == nil || q.asked[i/64]&(1<<(i%64)) == 0 {
		return nil
	}
	return &scan{done: closedCh, host: ip, up: q.up[i/64]&(1<<(i%64)) != 0, first: c.portsOf(ip)}
}

// claim gives the scan of ip: a new one the caller is to fill (mine), or the
// one another task holds, which is waited on.
func (c *Collector) claim(host, ip string) (s *scan, mine bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.byIP[ip]; ok {
		return s, false
	}
	if s := c.quietScan(ip); s != nil {
		return s, false
	}
	s = &scan{done: make(chan struct{}), host: host}
	c.byIP[ip] = s
	return s, true
}

// fill sets s to what r found.
func (s *scan) fill(r *scan) {
	s.open, s.silent, s.unprobed, s.up, s.capped, s.asked, s.err = r.open, r.silent, r.unprobed, r.up, r.capped, r.asked, r.err
	s.pass2, s.rest, s.asked2, s.first = r.pass2, r.rest, r.asked2, r.first
}

// topUp asks the ports of ports that scan s did not, and returns s with what
// they found. s is shared and left as it is.
func (c *Collector) topUp(ctx context.Context, host, ip string, s *scan, ports []int, found func(portscan.Open)) *scan {
	if !s.up || s.first == nil || len(ports) == 0 {
		return s
	}
	asked := make(map[int]bool, len(s.first)+len(s.rest))
	for _, p := range s.first {
		asked[p] = true
	}
	for _, p := range s.rest {
		asked[p] = true
	}
	var extra []int
	for _, p := range ports {
		if !asked[p] {
			extra = append(extra, p)
		}
	}
	if len(extra) == 0 {
		return s
	}
	r, err := c.Scanner.ScanEachFn(ctx, host, ip, extra, found)
	out := *s
	out.open = append(slices.Clone(s.open), r.Open...)
	sort.Slice(out.open, func(i, j int) bool { return out.open[i].Port < out.open[j].Port })
	out.silent = append(slices.Clone(s.silent), r.Silent...)
	out.unprobed += r.Unprobed
	out.capped = out.capped || r.Threshold
	out.first = slices.Concat(s.first, extra)
	out.err = err
	return &out
}

// claimRec is a range's claim on one address: settled once, when the
// address's scan is done or will not be.
type claimRec struct {
	c  *Collector
	ip string
	e  *scan
	o  sync.Once
}

func (r *claimRec) settle(s *scan) {
	r.o.Do(func() {
		r.e.fill(s)
		c := r.c
		c.mu.Lock()
		if c.byIP[r.ip] == r.e && (s.err != nil || len(s.open) == 0) {
			// Nothing to share but that the address was asked.
			delete(c.byIP, r.ip)
			if s.err == nil {
				c.markQuiet(r.ip, s.up)
			}
		}
		c.mu.Unlock()
		close(r.e.done)
	})
}

var errRangeStopped = errors.New("the range scan holding this address stopped before it was asked")
