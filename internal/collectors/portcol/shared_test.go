package portcol

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func countedCollector(ports []int) (*Collector, *atomic.Int64) {
	c := New(nil, ports, 0)
	var n atomic.Int64
	c.Scanner.Take = func() error { n.Add(1); return nil }
	c.Scanner.Give = func() {}
	return c, &n
}

func runBoth(t *testing.T, c *Collector, order string) {
	t.Helper()
	ctx := context.Background()
	emit := func(types.Observation) error { return nil }
	rng := func() {
		if _, err := c.Run(ctx, types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/30"}}, emit); err != nil {
			t.Error(err)
		}
	}
	named := func() {
		if _, err := c.Run(ctx, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}, emit); err != nil {
			t.Error(err)
		}
	}
	switch order {
	case "range first":
		rng()
		named()
	case "named first":
		named()
		rng()
	default:
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); rng() }()
		go func() { defer wg.Done(); named() }()
		wg.Wait()
	}
}

// An address a range holds and a target names is asked each port once, in
// whatever order the two come (#381).
func TestAnAddressOfARangeAndNamedIsAskedEachPortOnce(t *testing.T) {
	for _, order := range []string{"range first", "named first", "together"} {
		c, n := countedCollector([]int{55555, 55556})
		runBoth(t, c, order)
		if got := n.Load(); got != 8 {
			t.Errorf("%s: %d connects, want 8: 4 addresses of 2 ports", order, got)
		}
	}
}

// The port a target adds (the port of its URL) is asked too, once, though the
// range has scanned the address without it.
func TestANamedAddressIsAskedThePortsTheRangeDidNot(t *testing.T) {
	for _, order := range []string{"range first", "named first", "together"} {
		c, n := countedCollector([]int{55555, 55556})
		c.Also = map[string][]int{"127.0.0.1": {55557}}
		runBoth(t, c, order)
		if got := n.Load(); got != 9 {
			t.Errorf("%s: %d connects, want 9: 8 of the range and the target's port", order, got)
		}
	}
}

// A scan another task made of the address is topped up with the ports it did
// not ask, and no others.
func TestTopUpAsksOnlyThePortsTheScanDidNot(t *testing.T) {
	c, n := countedCollector([]int{55555, 55556})
	c.byIP["127.0.0.1"] = &scan{done: closedCh, host: "127.0.0.1", up: true, first: []int{55555}}
	emit := func(types.Observation) error { return nil }
	if _, err := c.Run(context.Background(), types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}, emit); err != nil {
		t.Fatal(err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("%d connects, want 1: the one port the scan had not asked", got)
	}
}
