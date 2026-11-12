package portcol

import (
	"context"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
)

// enterPass1 notes a scan that is asking its first pass; leave, which may be
// called any number of times, ends it.
func (c *Collector) enterPass1() (leave func()) {
	c.pass1.Add(1)
	var once sync.Once
	return func() { once.Do(func() { c.pass1.Add(-1) }) }
}

// beforePass2 holds a second pass until every first pass the run has is
// asked: the tasks waiting for a worker (the engine gives theirs up to them
// meanwhile) and the scans still in their first pass. Under a request cap the
// ports of the default set are then asked on every address before any other
// port of one that answered.
func (c *Collector) beforePass2(ctx context.Context) {
	catalog.Idle(ctx, Name)
	for c.pass1.Load() > 0 && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
}
