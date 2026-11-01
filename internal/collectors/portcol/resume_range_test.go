package portcol

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A block the budget stopped goes on with the addresses it had not finished:
// the addresses that answered nothing leave no row, and are asked no more than
// the ones with a row. The block's final row counts all of them.
func TestResumedRangeDoesNotAskAFinishedAddressAgain(t *testing.T) {
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/29"}}
	var takes atomic.Int32
	scan := func(c *Collector, budget int32) (obs []types.StoredObservation, err error) {
		takes.Store(0)
		c.Workers = 1
		c.Scanner.Detect = portscan.DetectNone
		c.Scanner.Take = func() error {
			if budget > 0 && takes.Add(1) > budget {
				return neterr.ErrBudget
			}
			if budget <= 0 {
				takes.Add(1)
			}
			return nil
		}
		_, err = c.Run(context.Background(), seed, func(o types.Observation) error {
			o.ObservedAt = time.Now()
			obs = append(obs, types.StoredObservation{Observation: o})
			return nil
		})
		return obs, err
	}
	first, err := scan(New(nil, []int{9}, 0), 3)
	if !errors.Is(err, neterr.ErrBudget) {
		t.Fatalf("the first scan: %v", err)
	}
	sweeps := Swept(first, time.Time{})
	if got := len(sweeps["127.0.0.0/29"].Done); got != 3 {
		t.Fatalf("the stopped block finished %d addresses: %+v", got, sweeps)
	}
	c := New(nil, []int{9}, 0)
	c.Apply(Config{Swept: sweeps})
	second, err := scan(c, 0)
	if err != nil {
		t.Fatalf("the second scan: %v", err)
	}
	if n := takes.Load(); n != 5 {
		t.Errorf("the second scan asked %d addresses, want the 5 the first did not finish", n)
	}
	var final map[string]any
	for _, r := range rows(t, []types.Observation{second[len(second)-1].Observation}) {
		final = r
	}
	if final["range"] != true || final["stopped"] != nil || final["addresses"] != float64(8) {
		t.Errorf("the block's last row: %v", final)
	}
	if _, left := Swept(append(first, second...), time.Time{})["127.0.0.0/29"]; left {
		t.Error("a finished block still reads as stopped")
	}
	// The seed of a finished address is the block's, not a scan of its own.
	if !c.Skip(types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1", "from": "prefix"}}) {
		t.Error("the seed of a finished address would scan it again")
	}
	if c.Skip(types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.6", "from": "prefix"}}) {
		t.Error("the seed of an address the block had not finished is skipped")
	}
}

// A stopped block's counts carry over to the row that finishes it: the
// address that answered before the stop is still counted in the total.
func TestResumedRangeKeepsTheCountsOfTheStoppedBlock(t *testing.T) {
	port := serve(t, "127.0.0.2:0")
	if _, err := net.Listen("tcp", "127.0.0.3:"+strconv.Itoa(port)); err != nil {
		t.Skip(err)
	}
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.0/29"}}
	run := func(c *Collector, budget int32) (obs []types.StoredObservation) {
		var n atomic.Int32
		c.Workers = 1
		c.Scanner.Detect = portscan.DetectNone
		c.Scanner.Take = func() error {
			if budget > 0 && n.Add(1) > budget {
				return neterr.ErrBudget
			}
			return nil
		}
		_, _ = c.Run(context.Background(), seed, func(o types.Observation) error {
			obs = append(obs, types.StoredObservation{Observation: o})
			return nil
		})
		return obs
	}
	// One port per address, so the budget stops the block after three addresses:
	// 127.0.0.2, which answered, is among them and 127.0.0.3 is not.
	first := run(New(nil, []int{port}, 0), 3)
	sw := Swept(first, time.Time{})["127.0.0.0/29"]
	if len(sw.Done) != 3 || sw.Counts["with_open"] != 1 {
		t.Fatalf("stopped block: done %v counts %v", sw.Done, sw.Counts)
	}
	c := New(nil, []int{port}, 0)
	c.Apply(Config{Swept: map[string]Sweep{"127.0.0.0/29": sw}})
	second := run(c, 0)
	got := rows(t, []types.Observation{second[len(second)-1].Observation})[0]
	if got["with_open"] != float64(2) || got["addresses"] != float64(8) {
		t.Errorf("the final row of the block: %v", got)
	}
}
