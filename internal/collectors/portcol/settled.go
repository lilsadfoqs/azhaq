package portcol

import "sync/atomic"

// settled counts the addresses this process's port scans have finished (an
// address a block's earlier run finished, or one the scope leaves out, is
// settled too): a progress line says how many of the run's addresses are done.
var settled atomic.Int64

// Settled is how many addresses the port scans of this process have finished.
func Settled() int64 { return settled.Load() }

// settle counts the address of scan s once, however many tasks (a range's, a
// name's) finish it.
func (c *Collector) settle(s *scan) {
	c.mu.Lock()
	if c.counted == nil {
		c.counted = map[*scan]bool{}
	}
	first := !c.counted[s]
	c.counted[s] = true
	c.mu.Unlock()
	if first {
		settled.Add(1)
	}
}
