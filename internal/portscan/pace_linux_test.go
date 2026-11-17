package portscan

import (
	"context"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lossyPath is a stand-in for a path that carries capacity connects a second:
// the SYNs over it are lost, as a router's queue loses them.
type lossyPath struct {
	mu       sync.Mutex
	capacity int
	window   time.Time
	count    int
	dropped  atomic.Int64
}

func (l *lossyPath) drop(string, int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.window) >= 100*time.Millisecond {
		l.window, l.count = now, 0
	}
	l.count++
	if l.count > l.capacity/10 {
		l.dropped.Add(1)
		return true
	}
	return false
}

// openPorts listens on 127.0.0.2 at some ports of [lo, hi).
func openPorts(t *testing.T, lo, hi, n int) []int {
	t.Helper()
	var open []int
	for p := lo + 37; p < hi && len(open) < n; p += (hi - lo) / n {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		open = append(open, p)
	}
	if len(open) < n/2 {
		t.Skip("the ports of the stand-in are taken")
	}
	return open
}

func openSet(r Report) []int {
	var out []int
	for _, o := range r.Open {
		out = append(out, o.Port)
	}
	slices.Sort(out)
	return out
}

// On a path that loses the connects over 3,000 a second, the adaptive pace
// finds the open ports the fixed 1500 a second does: it rises past 1500,
// backs off when connects time out, and the ports lost to it are asked again.
func TestAdaptivePaceFindsWhatTheFixedPaceDoes(t *testing.T) {
	const lo, hi = 21000, 25500
	open := openPorts(t, lo, hi, 40)
	var ports []int
	for p := lo; p < hi; p++ {
		ports = append(ports, p)
	}
	scan := func(s *Scanner, path *lossyPath) Report {
		s.init()
		s.pd.SimulateLoss(path.drop)
		r, err := s.ScanEach(context.Background(), "", "127.0.0.2", ports)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	fixedPath := &lossyPath{capacity: 3000}
	t0 := time.Now()
	fixed := openSet(scan(&Scanner{Rate: 1500, paceLoop: true, Detect: DetectNone, Seed: 7}, fixedPath))
	tFixed := time.Since(t0)
	if !slices.Equal(fixed, open) {
		t.Fatalf("the fixed pace found %v, want %v", fixed, open)
	}
	if fixedPath.dropped.Load() != 0 {
		t.Fatalf("the fixed pace of 1500 lost %d connects on a path of 3000", fixedPath.dropped.Load())
	}
	path := &lossyPath{capacity: 3000}
	s := &Scanner{paceLoop: true, Detect: DetectNone, Seed: 7}
	t0 = time.Now()
	got := openSet(scan(s, path))
	tAdaptive := time.Since(t0)
	if !slices.Equal(got, fixed) {
		t.Errorf("the adaptive pace found %v, the fixed one %v", got, fixed)
	}
	if path.dropped.Load() == 0 || s.pacer.Backoffs() == 0 {
		t.Errorf("%d connects lost, %d back-offs: the path did not bite, nothing was tried", path.dropped.Load(), s.pacer.Backoffs())
	}
	if s.pacer.peak <= DefaultRate {
		t.Errorf("the pace never rose above %g", s.pacer.peak)
	}
	t.Logf("fixed 1500/s %s; adaptive %s: peak %.0f/s, %d back-offs, %d connects lost and found again; open %v", tFixed.Round(time.Millisecond), tAdaptive.Round(time.Millisecond), s.pacer.peak, s.pacer.Backoffs(), path.dropped.Load(), got)
}

// A -rate given is a fixed ceiling: a scan on a path that loses nothing takes
// what the rate says, and the default pace on the same path is quicker.
func TestAGivenRateIsNeverPassed(t *testing.T) {
	var ports []int
	for p := 21000; p < 25500; p++ {
		ports = append(ports, p)
	}
	run := func(s *Scanner) time.Duration {
		s.paceLoop = true
		s.Detect = DetectNone
		t0 := time.Now()
		if _, err := s.ScanEach(context.Background(), "", "127.0.0.2", ports); err != nil {
			t.Fatal(err)
		}
		return time.Since(t0)
	}
	fixed := &Scanner{Rate: 3000}
	d := run(fixed)
	if fixed.pacer != nil || d < 1300*time.Millisecond {
		t.Errorf("4,500 connects at -rate 3000 took %s (adaptive %v), want at least 1.3 s", d, fixed.pacer != nil)
	}
	adaptive := &Scanner{}
	if d2 := run(adaptive); d2 >= d || adaptive.pacer.peak <= 3000 {
		t.Errorf("the default pace took %s against %s at 3000 and rose to %.0f: it did not rise over it", d2, d, adaptive.pacer.peak)
	}
}
