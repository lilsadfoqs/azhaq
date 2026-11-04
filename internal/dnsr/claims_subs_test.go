package dnsr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The second pass over the names a resolver dropped runs at a quarter of the
// first pass's concurrency.
func TestSecondPassRunsAtAQuarterOfTheConcurrency(t *testing.T) {
	p := New(Options{Timeout: 20 * time.Millisecond, Attempts: 1})
	var mu sync.Mutex
	seen := map[string]int{}
	var inflight, peak [3]atomic.Int32 // by pass
	p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		name := q.Question[0].Name
		mu.Lock()
		seen[name]++
		pass := seen[name]
		mu.Unlock()
		inflight[pass].Add(1)
		defer inflight[pass].Add(-1)
		for {
			cur := inflight[pass].Load()
			old := peak[pass].Load()
			if cur <= old || peak[pass].CompareAndSwap(old, cur) {
				break
			}
		}
		var i int
		fmt.Sscanf(strings.TrimPrefix(name, "h"), "%d", &i)
		if pass == 1 && i%2 == 0 { // dropped once, answered when asked again
			<-ctx.Done()
			return nil, errors.New("read udp: i/o timeout")
		}
		time.Sleep(5 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(name + " 60 IN A 192.0.2.1")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	for _, a := range p.ResolveMany(context.Background(), names(400), 64) {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s", a.Name, a.Status)
		}
	}
	if first, second := peak[1].Load(), peak[2].Load(); first < 32 || second < 2 || second > 16 {
		t.Errorf("%d queries in flight in the first pass of 64 workers and %d in the second: want up to 64 and up to a quarter, 16", first, second)
	}
}

// Resolvers that answer nothing are down, not busy: with 16 names or more and
// none answered there is no second pass. A smaller batch has one.
func TestNoSecondPassWhenNoneOfSixteenNamesOrMoreIsAnswered(t *testing.T) {
	for _, tc := range []struct{ names, queries int }{{10, 20}, {15, 30}, {16, 16}, {40, 40}} {
		p := New(Options{Timeout: 20 * time.Millisecond, Attempts: 1})
		var asked atomic.Int32
		p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
			asked.Add(1)
			<-ctx.Done()
			return nil, errors.New("read udp: i/o timeout")
		}
		p.ResolveMany(context.Background(), names(tc.names), 64)
		if got := int(asked.Load()); got != tc.queries {
			t.Errorf("%d names that nothing answers: %d queries, want %d", tc.names, got, tc.queries)
		}
	}
}
