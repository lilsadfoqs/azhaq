package portcol

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// sweepGate is a scanner Take that lets the first few connects through and
// holds the rest until the scheduler has been handed a seed: a scan that
// only hands its findings over at the end never gets there, and says so.
type sweepGate struct {
	free    int32
	asked   atomic.Int32
	handed  chan struct{}
	once    sync.Once
	timeout atomic.Bool
}

func newGate(free int) *sweepGate { return &sweepGate{free: int32(free), handed: make(chan struct{})} }

func (g *sweepGate) take() error {
	if g.asked.Add(1) <= g.free {
		return nil
	}
	select {
	case <-g.handed:
	case <-time.After(3 * time.Second):
		g.timeout.Store(true)
	}
	return nil
}

func (g *sweepGate) hints(mu *sync.Mutex, got *[]types.Seed) context.Context {
	return catalog.WithHints(context.Background(), func(seeds []types.Seed) {
		mu.Lock()
		*got = append(*got, seeds...)
		mu.Unlock()
		g.once.Do(func() { close(g.handed) })
	})
}

func webPort(t *testing.T, addr string) int {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go srv.Serve(l)
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

func hasSeed(seeds []types.Seed, typ types.SeedType, key string) bool {
	for _, s := range seeds {
		if s.Type == typ && s.Key() == key {
			return true
		}
	}
	return false
}

// An address of a range is handed on at its first open port, while the
// rest of its ports are still being asked: its own seed and its web port.
// What was handed on is not in the result again, and the seed is the
// range's, not a scan of its own.
func TestRangeHandsOnAnAddressWhileItIsScanned(t *testing.T) {
	port := webPort(t, "127.0.0.2:0")
	var ports []int
	for p := port; p < port+20; p++ {
		ports = append(ports, p)
	}
	g := newGate(1)
	c := New(nil, ports, 0)
	c.Scanner.Banner = 50 * time.Millisecond
	c.Scanner.Take = g.take
	var mu sync.Mutex
	var early []types.Seed
	meta, err := c.Run(g.hints(&mu, &early), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.2/32"}}, func(types.Observation) error { return nil })
	if err != nil || g.timeout.Load() {
		t.Fatalf("handed nothing before the sweep ended (%v): %v", g.timeout.Load(), err)
	}
	if !hasSeed(early, types.TypeIPAddress, "127.0.0.2") || !hasSeed(early, types.TypeURL, "http://127.0.0.2:"+strconv.Itoa(port)+"/") {
		t.Errorf("handed on early: %+v", early)
	}
	if len(meta.NextHints) != 0 {
		t.Errorf("seeds handed on early are in the result again: %+v", meta.NextHints)
	}
	ipSeed := types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.2", "from": "prefix"}}
	if !c.Skip(ipSeed) {
		t.Error("the address's seed would scan it again")
	}
	if c.Skip(types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.9", "from": "prefix"}}) ||
		c.Skip(types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.2"}}) {
		t.Error("a seed the range did not hand on is skipped")
	}
}

// A name's web port is handed on when found, not when its sweep ends.
func TestHostHandsOnAWebPortWhileItIsScanned(t *testing.T) {
	port := webPort(t, "127.0.0.1:0")
	var ports []int
	for p := port; p < port+20; p++ {
		ports = append(ports, p)
	}
	g := newGate(1)
	c := New(nil, ports, 0)
	c.Scanner.Banner = 50 * time.Millisecond
	c.Scanner.Take = g.take
	var mu sync.Mutex
	var early []types.Seed
	meta, err := c.Run(g.hints(&mu, &early), types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}, func(types.Observation) error { return nil })
	if err != nil || g.timeout.Load() {
		t.Fatalf("handed nothing before the sweep ended (%v): %v", g.timeout.Load(), err)
	}
	if len(early) != 1 || early[0].Type != types.TypeURL || len(meta.NextHints) != 0 {
		t.Errorf("early %+v, result %+v", early, meta.NextHints)
	}
}

// Without a scheduler to hear them, the seeds come back in the result as before.
func TestHandsOnReturnWhenNothingListens(t *testing.T) {
	port := webPort(t, "127.0.0.1:0")
	c := New(nil, []int{port}, 0)
	c.Scanner.Detect = portscan.DetectAll
	c.Scanner.Banner = 50 * time.Millisecond
	meta, err := c.Run(context.Background(), types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "127.0.0.1"}}, func(types.Observation) error { return nil })
	if err != nil || len(meta.NextHints) != 1 {
		t.Fatalf("%+v %v", meta.NextHints, err)
	}
}

// An address of a range has a row for its open port while its other ports are
// still being asked, not when the block ends: the scan holds its next connect
// until a row with the port has been written, and says so if none comes.
func TestRangeWritesAnOpenPortAsItIsFound(t *testing.T) {
	port := webPort(t, "127.0.0.2:0")
	ports := []int{port}
	for p := port + 1; p < port+20; p++ {
		ports = append(ports, p)
	}
	g := newGate(1)
	c := New(nil, ports, 0)
	c.Workers = 1
	c.Discover = DiscoverOff
	c.Scanner.Detect = portscan.DetectNone
	c.Scanner.Take = g.take
	var rowsAtFind []map[string]any
	var all []types.Observation
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypePrefix, Keys: map[string]string{"prefix": "127.0.0.2/31"}}, func(o types.Observation) error {
		all = append(all, o)
		var m map[string]any
		if json.Unmarshal(o.Payload, &m) == nil && m["checkpoint"] == true && m["ip"] == "127.0.0.2" {
			if rowsAtFind == nil {
				g.once.Do(func() { close(g.handed) }) // the scan may go on
			}
			rowsAtFind = append(rowsAtFind, m)
		}
		return nil
	})
	if err != nil || g.timeout.Load() {
		t.Fatalf("no row for the open port before the scan ended (%v): %v", g.timeout.Load(), err)
	}
	if svc, _ := rowsAtFind[0]["services"].([]any); len(svc) != 1 || rowsAtFind[0]["prefix"] != "127.0.0.2/31" || !(rowsAtFind[0]["partial"] == true) {
		t.Errorf("the early row: %v", rowsAtFind[0])
	}
	// The address's own row at the end is a whole scan, which a resume reads as done.
	var final map[string]any
	for _, m := range rows(t, all) {
		if m["ip"] == "127.0.0.2" && m["checkpoint"] != true {
			final = m
		}
	}
	if final == nil || final["partial"] == true {
		t.Errorf("the address's last row: %v", final)
	}
	if left := Priors(func() []types.StoredObservation {
		var out []types.StoredObservation
		for _, o := range all {
			out = append(out, types.StoredObservation{Observation: o})
		}
		return out
	}()); len(left) != 0 {
		t.Errorf("a finished address still reads as stopped: %v", left)
	}
}
