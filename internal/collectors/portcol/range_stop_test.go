package portcol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A kill file met while the connects wait for the pace ends the block as any
// stop does: the run's error says so, the block lists the addresses it
// finished (not all of them), and a resume asks the rest, each port once.
func TestKillFileInTheRangeStageStopsAndResumes(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	egress.SetRate(1e6)
	kill := filepath.Join(t.TempDir(), "run.stop")
	stopWatch := egress.SetKill(kill)
	defer func() { stopWatch() }()

	const addrs, perAddr = 8, 20
	ports := make([]int, perAddr)
	for i := range ports {
		ports[i] = 40000 + i
	}
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.8.0/29"}}
	var takes atomic.Int32
	run := func(c *Collector, touchAt int32) (obs []types.StoredObservation, err error) {
		c.Workers = 1
		c.Scanner.Detect = portscan.DetectNone
		c.Scanner.Take = func() error {
			// Counted as a send is: the file is seen by the next wait for the pace.
			if n := takes.Add(1); n == touchAt {
				_ = os.WriteFile(kill, nil, 0o644)
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
	first, err := run(New(nil, ports, 0), 3*perAddr+5)
	if !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("the first scan ended with %v, want the kill file", err)
	}
	sw := Swept(first, time.Time{})["127.0.8.0/29"]
	if n := len(sw.Done); n < 1 || n >= addrs {
		t.Fatalf("the stopped block finished %d of %d addresses: %+v", n, addrs, sw)
	}
	asked := takes.Load()
	if asked < 3*perAddr || asked >= addrs*perAddr {
		t.Fatalf("%d connects before the stop, want a part of the %d", asked, addrs*perAddr)
	}

	// Removed: the next scan is let go, and goes on from what the first kept.
	_ = os.Remove(kill)
	stopWatch()
	stopWatch = egress.SetKill(kill)
	c := New(nil, ports, 0)
	c.Apply(Config{Swept: Swept(first, time.Time{}), Prior: Priors(first)})
	second, err := run(c, -1)
	if err != nil {
		t.Fatalf("the resumed scan: %v", err)
	}
	last := rows(t, []types.Observation{second[len(second)-1].Observation})[0]
	if last["range"] != true || last["stopped"] != nil || last["addresses"] != float64(addrs) {
		t.Errorf("the resumed block's last row: %v", last)
	}
	// An address the stop cut is asked again from its first port: its in-flight
	// connects are repeated, never the addresses that were finished.
	if total := int(takes.Load()); total < addrs*perAddr || total > addrs*perAddr+perAddr {
		t.Errorf("%d connects over both scans, want %d and at most one address repeated", total, addrs*perAddr)
	}
}

// A deadline or an interrupt ends the block as a limit does: the addresses it
// finished and the part-asked one are kept, what is left is counted from them,
// and a resume asks it with no port repeated but the in-flight ones.
func TestDeadlineInTheRangeStageKeepsWhatWasAsked(t *testing.T) {
	const addrs, perAddr = 8, 20
	ports := make([]int, perAddr)
	for i := range ports {
		ports[i] = 40000 + i
	}
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.8.0/29"}}
	var takes atomic.Int32
	run := func(cfg Config, cutAt int32) (obs []types.StoredObservation, err error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := New(nil, ports, 0)
		c.Apply(cfg)
		c.Workers = 1
		c.Scanner.Detect = portscan.DetectNone
		c.Scanner.Take = func() error {
			if takes.Add(1) == cutAt {
				time.Sleep(50 * time.Millisecond) // the connects before it answer first
				cancel()
			}
			return nil
		}
		_, err = c.Run(ctx, seed, func(o types.Observation) error {
			o.ObservedAt = time.Now()
			obs = append(obs, types.StoredObservation{Observation: o})
			return nil
		})
		return obs, err
	}
	first, err := run(Config{}, 3*perAddr+15)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the first scan ended with %v", err)
	}
	sw := Swept(first, time.Time{})["127.0.8.0/29"]
	if len(sw.Done) != 3 {
		t.Fatalf("the stopped block finished %v, want 3 addresses: %+v", sw.Done, sw)
	}
	left, leftPorts := NotAsked(first, perAddr)
	if left != addrs-3 || leftPorts < addrs*perAddr-int(takes.Load()) || leftPorts >= addrs*perAddr-3*perAddr {
		t.Errorf("left unasked: %d addresses, %d ports after %d connects; want %d addresses and fewer ports than the five hold whole", left, leftPorts, takes.Load(), addrs-3)
	}
	second, err := run(Config{Swept: Swept(first, time.Time{}), Prior: Priors(first)}, -1)
	if err != nil {
		t.Fatalf("the resumed scan: %v", err)
	}
	if total := int(takes.Load()); total < addrs*perAddr || total > addrs*perAddr+perAddr {
		t.Errorf("%d connects over both scans, want %d and at most one address repeated", total, addrs*perAddr)
	}
	if last := rows(t, []types.Observation{second[len(second)-1].Observation})[0]; last["addresses"] != float64(addrs) || last["stopped"] != nil {
		t.Errorf("the resumed block's last row: %v", last)
	}
}
