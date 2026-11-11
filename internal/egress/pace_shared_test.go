package egress

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A batch larger than the burst is paced in parts, not refused.
func TestPaceNTakesABatchLargerThanTheBurst(t *testing.T) {
	Reset()
	defer Reset()
	SetRate(100) // a burst of 20
	t0 := time.Now()
	if err := PaceN(context.Background(), 60); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d < 350*time.Millisecond {
		t.Errorf("60 places at 100/s took %s", d)
	}
}

// DNS queries to a target's own name server are paced by -rate.
func TestDNSQueriesToATargetsServerArePacedByRate(t *testing.T) {
	Reset()
	defer Reset()
	SetRate(5) // a burst of 1, then one every 200 ms
	addr, got := fakeDNS(t)
	x := NewDNSExchanger(time.Second, "")
	t0 := time.Now()
	for i := 0; i < 4; i++ {
		q := new(dns.Msg)
		q.SetQuestion("a.test.", dns.TypeA)
		if _, err := x.ExchangeAt(context.Background(), q, addr); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(t0); d < 550*time.Millisecond || got.Load() != 4 {
		t.Errorf("4 queries at 5/s took %s, the server got %d", d, got.Load())
	}
}
