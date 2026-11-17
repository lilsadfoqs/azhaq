package portcol

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// The second pass an address was stopped before is kept: a block cut in its
// first pass leaves, for each address that answered it, a row saying the first
// pass was asked whole, so a resume goes on to the second and asks no first-pass
// port twice. What the block left unasked is those second passes too.
func TestBlockStoppedInPassOneKeepsTheAddressesThatAnswered(t *testing.T) {
	first := serve(t, "127.0.8.0:0")
	serve(t, "127.0.8.1:"+strconv.Itoa(first))
	seed := types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.8.0/30"}}
	var mu sync.Mutex
	opened := map[string]int{}
	run := func(cfg Config, budget int32) (obs []types.StoredObservation) {
		var n atomic.Int32
		c := New(nil, []int{first}, 0)
		cfg.Escalate = true
		c.Apply(cfg)
		c.Workers = 1
		c.Scanner.Detect = portscan.DetectNone
		c.Scanner.Take = func() error {
			if n.Add(1) > budget {
				return neterr.ErrBudget
			}
			return nil
		}
		c.Scanner.Opened = func(ip string, p int) {
			if p == first {
				mu.Lock()
				opened[ip]++
				mu.Unlock()
			}
		}
		_, _ = c.Run(context.Background(), seed, func(o types.Observation) error {
			o.ObservedAt = time.Now()
			obs = append(obs, types.StoredObservation{Observation: o})
			return nil
		})
		return obs
	}
	// Three addresses asked their first pass (one port each): .0 and .1 answered.
	stopped := run(Config{}, 3)
	addrs, ports := NotAsked(stopped, 1)
	if wantP := 1 + 2*(65535-1); addrs != 3 || ports != wantP {
		t.Errorf("left unasked: %d addresses, %d ports; want 3 (the one not reached and the two second passes), %d", addrs, ports, wantP)
	}
	run(Config{Swept: Swept(stopped, time.Time{}), Prior: Priors(stopped)}, 3)
	mu.Lock()
	defer mu.Unlock()
	for _, ip := range []string{"127.0.8.0", "127.0.8.1"} {
		if opened[ip] != 1 {
			t.Errorf("%s was asked its first-pass port %d times over the stop and the resume, want once", ip, opened[ip])
		}
	}
}

// An address a stopped run asked the whole first pass of is held by the block
// and by its own address seed: the second pass goes on once, not in both.
func TestResumedSecondPassIsNotAskedByTwoTasks(t *testing.T) {
	const ip = "127.0.8.9"
	keep := map[int]bool{}
	for p := 30000; p < 30040; p++ {
		keep[p] = true
	}
	var noPorts []int
	for p := 1; p <= 65535; p++ {
		if !keep[p] {
			noPorts = append(noPorts, p)
		}
	}
	var takes atomic.Int32
	c := New(nil, []int{80}, 0)
	c.Apply(Config{Escalate: true, NoPorts: noPorts, Prior: map[string]Prior{ip: {Asked: []int{80}, Open: []portscan.Open{{Port: 80}}}}})
	c.Scanner.Detect = portscan.DetectNone
	c.Scanner.Take = func() error { takes.Add(1); return nil }
	var wg sync.WaitGroup
	for _, seed := range []types.Seed{
		{Type: types.TypePrefix, Keys: map[string]string{"prefix": ip + "/32"}},
		{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip, "from": "prefix"}},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Run(context.Background(), seed, func(types.Observation) error { return nil })
		}()
	}
	wg.Wait()
	if n := takes.Load(); n != int32(len(keep)) {
		t.Errorf("%d connects for the %d ports of the second pass: two tasks asked it", n, len(keep))
	}
}
