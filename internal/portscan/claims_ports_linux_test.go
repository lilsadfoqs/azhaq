package portscan

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A port that neither accepts nor refuses (a full accept queue drops the
// SYN) is asked again once by default, N more times with -retries N, never
// with a negative Retries (-retries 0 on the command line); each ask is a
// counted connect.
func TestRetriesAskTheSilentPortThatManyMoreTimes(t *testing.T) {
	stuck, _ := fullListener(t)
	for retries, want := range map[int]int32{-1: 1, 0: 2, 1: 2, 3: 4} {
		var takes atomic.Int32
		s := &Scanner{Detect: DetectNone, Retries: retries, Timeout: 150 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
		r, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{stuck})
		if err != nil || len(r.Open) != 0 || len(r.Silent) != 1 || r.Silent[0] != stuck {
			t.Fatalf("Retries %d: open %v silent %v, %v", retries, r.Open, r.Silent, err)
		}
		if takes.Load() != want {
			t.Errorf("Retries %d: %d connects counted, want %d", retries, takes.Load(), want)
		}
	}
}

// An address is up when a connect to 80 or 443 is accepted or refused, asked
// twice; one that stays silent on both is called down. Each connect is
// counted.
func TestUpIsAcceptedOrRefusedAndSilenceTwiceIsDown(t *testing.T) {
	saved := DiscoveryPorts
	t.Cleanup(func() { DiscoveryPorts = saved })
	open, stop := listener(t)
	defer stop()
	gone, stop2 := listener(t)
	stop2()
	time.Sleep(20 * time.Millisecond)
	stuck, _ := fullListener(t)
	for _, c := range []struct {
		name  string
		ports []int
		up    bool
		takes int32
	}{
		{"accepted", []int{open}, true, 1},
		{"refused", []int{gone}, true, 1},
		{"silent on both, asked twice", []int{stuck, stuck}, false, 4},
		{"silent on one, refused on the other", []int{stuck, gone}, true, 2},
	} {
		DiscoveryPorts = c.ports
		var takes atomic.Int32
		s := &Scanner{Timeout: 150 * time.Millisecond, Take: func() error { takes.Add(1); return nil }}
		up, err := s.Up(context.Background(), "", "127.0.0.1")
		if err != nil || up != c.up || takes.Load() != c.takes {
			t.Errorf("%s: up %v (%v), %d connects, want %v and %d", c.name, up, err, takes.Load(), c.up, c.takes)
		}
	}
}
