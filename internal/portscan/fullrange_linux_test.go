package portscan

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// closedPorts are n loopback ports nothing listens on.
func closedPorts(t *testing.T, n int) []int {
	t.Helper()
	var ls []net.Listener
	var ports []int
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range ls {
		l.Close()
	}
	return ports
}

// standIn is a loopback host of a few open ports, one that drops connects
// (a full accept queue: filtered) and many closed ones.
func standIn(t *testing.T) (open []int, stuck int, closed, all []int) {
	t.Helper()
	for i := 0; i < 3; i++ {
		p, stop := listener(t)
		t.Cleanup(stop)
		open = append(open, p)
	}
	stuck, _ = fullListener(t)
	closed = closedPorts(t, 300)
	all = slices.Concat(open, []int{stuck}, closed)
	slices.Sort(all)
	return
}

// A full-range scan counts the same open, closed and filtered ports, and
// writes one ledger line for each connect, whether the connects go out in
// batches or one at a time, and whether the wait for a silent port follows
// the round trip (no -connect-timeout) or is the one given.
func TestFullRangeCountsAreTheSameOnEveryPath(t *testing.T) {
	open, stuck, closed, all := standIn(t)
	slices.Sort(open)
	for _, tt := range []struct {
		name    string
		rate    float64
		timeout time.Duration
	}{
		{"batches, wait follows the round trip", 10000, 0},
		{"batches, timeout given", 10000, 400 * time.Millisecond},
		{"one at a time, wait follows the round trip", 200, 0},
		{"one at a time, timeout given", 200, 400 * time.Millisecond},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "l.jsonl")
			l, err := ledger.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			ledger.Use(l)
			defer ledger.Use(nil)
			var takes atomic.Int32
			s := &Scanner{Rate: tt.rate, Timeout: tt.timeout, Detect: DetectNone, Retries: -1, Take: func() error { takes.Add(1); return nil }}
			r, err := s.ScanEach(context.Background(), "", "127.0.0.1", all)
			if err != nil {
				t.Fatal(err)
			}
			l.Close()
			var found []int
			for _, o := range r.Open {
				found = append(found, o.Port)
			}
			slices.Sort(found)
			if !slices.Equal(found, open) {
				t.Errorf("open %v, want %v", found, open)
			}
			if !slices.Equal(r.Silent, []int{stuck}) {
				t.Errorf("filtered %v, want [%d]", r.Silent, stuck)
			}
			if got := r.Asked - len(r.Open) - len(r.Silent); r.Asked != len(all) || got != len(closed) {
				t.Errorf("asked %d, closed %d, want %d and %d", r.Asked, got, len(all), len(closed))
			}
			if int(takes.Load()) != len(all) {
				t.Errorf("%d connects counted, want %d", takes.Load(), len(all))
			}
			lines := 0
			if err := ledger.Read(path, func(e ledger.Entry) error {
				if e.Kind == "tcp" && e.IsTarget() {
					lines++
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if lines != len(all) {
				t.Errorf("%d ledger lines, want one for each of the %d connects", lines, len(all))
			}
		})
	}
}

// A port that never answers does not hold the scan for the whole connect
// timeout once the other ports have shown the round trip; a timeout that was
// asked for is waited in full.
func TestSilentPortIsGivenUpOnAfterTheRoundTrip(t *testing.T) {
	_, stuck, _, all := standIn(t)
	took := func(timeout time.Duration) time.Duration {
		s := &Scanner{Rate: 10000, Timeout: timeout, Detect: DetectNone, Retries: -1}
		t0 := time.Now()
		r, err := s.ScanEach(context.Background(), "", "127.0.0.1", all)
		if err != nil || !slices.Equal(r.Silent, []int{stuck}) {
			t.Fatalf("filtered %v, %v", r.Silent, err)
		}
		return time.Since(t0)
	}
	if d := took(0); d > 1000*time.Millisecond {
		t.Errorf("a silent port held the scan for %s, the default timeout is 1.5 s", d)
	}
	if d := took(700 * time.Millisecond); d < 650*time.Millisecond {
		t.Errorf("-connect-timeout 700ms was cut short: %s", d)
	}
}
