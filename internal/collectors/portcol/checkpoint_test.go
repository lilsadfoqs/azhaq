package portcol

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A scan killed while it goes has left the ports it had finished: the
// resume asks the ports after them and finds what both runs found.
func TestKilledScanResumesAfterItsCheckpoint(t *testing.T) {
	early := listener(t)
	late := early + 2900
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(late))
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	var ports []int
	lo := early
	for p := lo - 3; p < lo+3000; p++ {
		ports = append(ports, p)
	}
	seed := types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}
	var rows []types.StoredObservation
	scan := func(c *Collector, ctx context.Context) (types.RunMeta, error) {
		return c.Run(ctx, seed, func(o types.Observation) error {
			o.ObservedAt = time.Now()
			rows = append(rows, types.StoredObservation{Observation: o})
			return nil
		})
	}
	c := New(nil, ports, 1000)
	c.Apply(Config{Order: portscan.OrderAscending, Detect: portscan.DetectNone})
	// Killed: the process goes with no row of its own; what is left is what
	// the scan kept while it went.
	ctx, cancel := context.WithTimeout(context.Background(), 1700*time.Millisecond)
	defer cancel()
	_, _ = scan(c, ctx)
	prior := Priors(rows)["127.0.0.1"]
	if len(prior.Asked) < 700 || len(prior.Asked) > len(ports)-700 {
		t.Fatalf("the scan kept %d of %d ports after 1.7 s at 1000 a second", len(prior.Asked), len(ports))
	}
	asked, _ := places(portscan.Compact(prior.Asked))
	if asked[0] != ports[0] || asked[len(asked)-1] != ports[len(asked)-1] {
		t.Errorf("what was kept is not the ports from the first: %d..%d", asked[0], asked[len(asked)-1])
	}

	var takes atomic.Int32
	rows = rows[:0]
	c2 := New(nil, ports, 100000)
	c2.Apply(Config{Order: portscan.OrderAscending, Detect: portscan.DetectNone, Prior: map[string]Prior{"127.0.0.1": prior}})
	c2.Scanner.Take = func() error { takes.Add(1); return nil }
	if _, err := scan(c2, context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, want := int(takes.Load()), len(ports)-len(prior.Asked); n != want {
		t.Errorf("the resume asked %d ports, want the %d not kept", n, want)
	}
	var final struct {
		Scanned int   `json:"scanned"`
		Open    []int `json:"open"`
		Partial bool  `json:"partial"`
	}
	if err := json.Unmarshal(rows[len(rows)-1].Payload, &final); err != nil {
		t.Fatal(err)
	}
	if final.Partial || final.Scanned != len(ports) || !slices.Contains(final.Open, early) || !slices.Contains(final.Open, late) {
		t.Errorf("final row %s", rows[len(rows)-1].Payload)
	}
}

func listener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// A block of a range keeps the addresses it has finished while it goes, as a
// stopped block does: a kill in the middle leaves them swept, with the counts
// of what they were, and the resume does not ask them again.
func TestKilledBlockKeepsItsFinishedAddresses(t *testing.T) {
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/29"}}
	var rows []types.StoredObservation
	var takes atomic.Int32
	run := func(c *Collector, ctx context.Context) {
		c.Workers = 1
		c.Apply(Config{Detect: portscan.DetectNone, Swept: c.Swept})
		c.Scanner.Take = func() error { takes.Add(1); return nil }
		_, _ = c.Run(ctx, seed, func(o types.Observation) error {
			o.ObservedAt = time.Now()
			rows = append(rows, types.StoredObservation{Observation: o})
			return nil
		})
	}
	// Ten ports an address at 20 connects a second: half a second each.
	ports := []int{9, 10, 11, 12, 13, 14, 15, 16, 17, 18}
	ctx, cancel := context.WithTimeout(context.Background(), 2900*time.Millisecond)
	defer cancel()
	run(New(nil, ports, 20), ctx)
	sw := Swept(rows, time.Time{})["127.0.0.0/29"]
	if n := len(sw.Done); n < 2 || n > 6 {
		t.Fatalf("the killed block left %d addresses swept: %+v", n, sw)
	}
	for _, r := range rows {
		var p struct {
			Addresses int  `json:"addresses"`
			Range     bool `json:"range"`
		}
		if json.Unmarshal(r.Payload, &p); p.Range && p.Addresses != len(sw.Done) && p.Addresses > len(sw.Done) {
			t.Errorf("a checkpoint says %d addresses, the newest sweeps %d", p.Addresses, len(sw.Done))
		}
	}
	takes.Store(0)
	rows = rows[:0]
	c := New(nil, ports, 100000)
	c.Apply(Config{Swept: map[string]Sweep{"127.0.0.0/29": sw}})
	run(c, context.Background())
	if want := (8 - len(sw.Done)) * len(ports); int(takes.Load()) != want {
		t.Errorf("the resume asked %d ports, want %d (the addresses not swept)", takes.Load(), want)
	}
}
