package portscan

import (
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// A snapshot is the ports finished before the first still on its way; a port
// that timed out or is awaited again is left out of what was asked, and the
// open ones are those inside the prefix.
func TestProgressSnapshotIsTheFinishedPrefix(t *testing.T) {
	p := &progress{ports: []int{10, 20, 30, 40, 50, 60}, state: make([]uint8, 6), opens: map[int]Open{}}
	p.done(0, portClosed, Open{}, false)
	p.done(1, portOpen, Open{Port: 20, Service: "http"}, false)
	p.done(2, portTimedOut, Open{}, false)
	p.done(3, portOpen, Open{Port: 40, again: true}, false)
	p.done(5, portClosed, Open{}, false) // finished beyond one that is not
	p.done(4, portClosed, Open{}, true)  // cut off by a cancel
	if got := p.snapshot(5); !reflect.DeepEqual(got.Asked, []int{10, 20}) || len(got.Open) != 1 || got.Open[0].Port != 20 {
		t.Errorf("five asked: %+v", got)
	}
	q := &progress{ports: []int{10, 20, 30}, state: make([]uint8, 3), opens: map[int]Open{}}
	q.done(0, portClosed, Open{}, false)
	q.done(2, portClosed, Open{}, false)
	if got := q.snapshot(3); !reflect.DeepEqual(got.Asked, []int{10}) {
		t.Errorf("a port still on its way: %+v", got)
	}
	if got := q.snapshot(1); !reflect.DeepEqual(got.Asked, []int{10}) {
		t.Errorf("only one asked: %+v", got)
	}
}

// A scan that lasts reports what it finished while it goes, in the order it
// asked, with the open ports among them; one that ends in a second does not.
func TestScanReportsProgressWhileItGoes(t *testing.T) {
	open := listen(t, func(c net.Conn) {})
	var ports []int
	for p := open - 5; p < open+2995; p++ {
		ports = append(ports, p)
	}
	var mu sync.Mutex
	var got []Progress
	ctx := WithProgress(t.Context(), func(p Progress) {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	})
	s := &Scanner{Rate: 1000, Detect: DetectNone}
	t0 := time.Now()
	r, err := s.ScanEach(ctx, "", "127.0.0.1", ports)
	if err != nil || len(r.Open) < 1 {
		t.Fatalf("%v %+v", err, r)
	}
	if time.Since(t0) < 2*time.Second {
		t.Fatalf("the scan took %v: too short to be checked", time.Since(t0))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("%d progress calls in a scan of %v", len(got), time.Since(t0))
	}
	for i, p := range got {
		if i > 0 && len(p.Asked) < len(got[i-1].Asked) {
			t.Errorf("call %d has %d ports after %d", i, len(p.Asked), len(got[i-1].Asked))
		}
		for j, port := range p.Asked {
			if port != ports[j] {
				t.Fatalf("call %d: asked[%d] is %d, want %d (ascending order)", i, j, port, ports[j])
			}
		}
	}
	first, last := got[0], got[len(got)-1]
	if len(first.Asked) < 500 || len(first.Asked) > 1500 {
		t.Errorf("after the first second %d ports were finished, at 1000 a second", len(first.Asked))
	}
	if len(last.Asked) < len(ports)-3 {
		t.Errorf("the last call has %d of %d ports", len(last.Asked), len(ports))
	}
	found := false // another listener of the machine may be in the range
	for _, o := range last.Open {
		found = found || o.Port == open
	}
	if !found {
		t.Errorf("open ports of the last call: %+v", last.Open)
	}
	quick := &Scanner{Detect: DetectNone}
	calls := 0
	qctx := WithProgress(t.Context(), func(Progress) { calls++ })
	if _, err := quick.ScanEach(qctx, "", "127.0.0.1", ports[:200]); err != nil || calls != 0 {
		t.Errorf("a quick scan made %d progress calls (err %v)", calls, err)
	}
}
