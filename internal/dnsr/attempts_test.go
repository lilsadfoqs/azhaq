package dnsr

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// A generated name (brute force, permutations, a source's guesses, the name
// history) is asked twice, as dnsx's default, unless -retry gives the
// attempts; any other name keeps three.
func TestGeneratedNamesAreAskedTwiceUnlessRetryIsGiven(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     Options
		bulk     bool
		attempts int64
	}{
		{"a generated name", Options{}, true, 2},
		{"a name from a source", Options{}, false, 3},
		{"-retry 4 holds for a generated name", Options{Attempts: 4}, true, 4},
		{"-retry 1 asks once", Options{Attempts: 1}, true, 1},
	} {
		var asked atomic.Int64
		tc.opts.Resolvers, tc.opts.PerSecond = []string{"192.0.2.1:53"}, -1
		p := New(tc.opts)
		p.Exchange = func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
			asked.Add(1)
			return nil, errors.New("i/o timeout")
		}
		ctx := context.Background()
		if tc.bulk {
			ctx = Bulk(ctx)
		}
		if a := p.Resolve(ctx, "x.example.org"); a.Status != StatusFailed || asked.Load() != tc.attempts {
			t.Errorf("%s: %d queries, status %v, want %d", tc.name, asked.Load(), a.Status, tc.attempts)
		}
	}
}

// The second pass over the names that failed asks a spread sample of them
// once each: when none answers, the zone is silent and the rest are left,
// at 16 queries, not every attempt of 16 names again.
func TestSecondPassProbeAsksEachSampledNameOnce(t *testing.T) {
	var asked atomic.Int64
	p := New(Options{Resolvers: []string{"192.0.2.1:53"}, PerSecond: -1})
	p.Exchange = func(_ context.Context, m *dns.Msg, _ string) (*dns.Msg, error) {
		asked.Add(1)
		if m.Question[0].Name[0] == 'a' { // answered: it does not exist
			r := new(dns.Msg)
			r.SetRcode(m, dns.RcodeNameError)
			return r, nil
		}
		return nil, errors.New("i/o timeout")
	}
	var names []string
	for i := 0; i < 10; i++ {
		names = append(names, fmt.Sprintf("a%d.example.org", i))
	}
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("s%d.example.org", i))
	}
	p.ResolveMany(Bulk(context.Background()), names, 4)
	// 10 answered, 40 silent names asked twice, then the probe's 16.
	if got, want := asked.Load(), int64(10+40*2+16); got != want {
		t.Errorf("%d queries, want %d", got, want)
	}
}

// With every resolver silent and so passed over, the ones asked still take
// turns: one is not asked every time, which would halve the pace set for the
// pool.
func TestResolversThatAllFailAreStillAskedInTurn(t *testing.T) {
	var mu sync.Mutex
	by := map[string]int{}
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, PerSecond: -1})
	p.Exchange = func(_ context.Context, _ *dns.Msg, server string) (*dns.Msg, error) {
		mu.Lock()
		by[server]++
		mu.Unlock()
		return nil, errors.New("i/o timeout")
	}
	for i := 0; i < 100; i++ {
		p.Resolve(Bulk(context.Background()), fmt.Sprintf("s%d.example.org", i))
	}
	mu.Lock()
	defer mu.Unlock()
	lo, hi := min(by["192.0.2.1:53"], by["192.0.2.2:53"]), max(by["192.0.2.1:53"], by["192.0.2.2:53"])
	if lo*3 < hi {
		t.Errorf("queries by resolver %v: one is asked far more than the other", by)
	}
}
