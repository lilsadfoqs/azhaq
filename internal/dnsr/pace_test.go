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

// slowLive answers every A question after d with an address.
func slowLive(d time.Duration, asked *atomic.Int32) func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
	return func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		asked.Add(1)
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		return m, nil
	}
}

func names(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%d.example.org", i)
	}
	return out
}

// 700 names with no pace take what dnsx -t 100 takes: names / threads
// round trips, not more. Resolvers answering in 20 ms, 128 queries in
// flight: 6 rounds of 20 ms, so under a second with room for a slow CI.
func TestResolveManyAsFastAsDnsxAtItsDefaults(t *testing.T) {
	p := New(Options{})
	var asked atomic.Int32
	p.Exchange = slowLive(20*time.Millisecond, &asked)
	t0 := time.Now()
	out := p.ResolveMany(context.Background(), names(700), 128)
	took := time.Since(t0)
	for _, a := range out {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
	if took > time.Second {
		t.Errorf("700 names took %s with 128 in flight and 20 ms a query", took)
	}
	if n := asked.Load(); n != 700 {
		t.Errorf("%d queries for 700 live names: one each is enough", n)
	}
}

// -dns-rate is per resolver and the default pool has six, so 700 names at
// -dns-rate 100 go out at 600 queries a second, a second and a bit: the
// pace is spread over the resolvers, not spent on one.
func TestResolveManyPaceIsPerResolver(t *testing.T) {
	p := New(Options{PerSecond: 100})
	var asked atomic.Int32
	p.Exchange = slowLive(time.Millisecond, &asked)
	t0 := time.Now()
	p.ResolveMany(context.Background(), names(700), 128)
	took := time.Since(t0)
	if took < 700*time.Millisecond || took > 3*time.Second {
		t.Errorf("700 queries at 100 a second on 6 resolvers took %s, want about 1.2 s", took)
	}
}

// One resolver that refuses this machine does not hold the run back: the
// names are answered by the others.
func TestResolveManyPastARefusingResolver(t *testing.T) {
	p := New(Options{})
	var asked atomic.Int32
	live := slowLive(time.Millisecond, &asked)
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if strings.HasPrefix(server, "8.8.8.8") {
			m := new(dns.Msg)
			m.SetRcode(q, dns.RcodeRefused)
			return m, nil
		}
		return live(ctx, q, server)
	}
	out := p.ResolveMany(context.Background(), names(300), 128)
	for _, a := range out {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
}

// A name no resolver answered says which resolver failed last and why.
func TestFailedAnswerNamesTheResolver(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.53"}})
	p.Exchange = func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeRefused)
		return m, nil
	}
	a := p.Resolve(context.Background(), "x.example.org")
	if a.Status != StatusFailed || a.Resolver != "192.0.2.53:53" || !strings.Contains(a.Err, "REFUSED") {
		t.Errorf("%+v", a)
	}
}

// Resolvers that answer nothing are found out in one pass: asking every
// name again at a quarter of the speed would take minutes more for the same
// failures. The names say they got no answer.
func TestResolveManyDoesNotRepeatAPassWithNoAnswer(t *testing.T) {
	p := New(Options{Timeout: 30 * time.Millisecond})
	var asked atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		asked.Add(1)
		select {
		case <-time.After(30 * time.Millisecond):
		case <-ctx.Done():
		}
		return nil, errors.New("read udp: i/o timeout")
	}
	t0 := time.Now()
	out := p.ResolveMany(context.Background(), names(200), 128)
	took := time.Since(t0)
	for _, a := range out {
		if a.Status != StatusFailed || a.Resolver == "" {
			t.Fatalf("%+v", a)
		}
	}
	if n := asked.Load(); n > 200*3 {
		t.Errorf("%d queries for 200 names at 3 attempts each: a second pass was made", n)
	}
	if took > 2*time.Second {
		t.Errorf("took %s", took)
	}
}

// A query whose datagram is lost is not waited out for the whole timeout:
// the next attempt is sent beside it once the first is late, and answers.
func TestLostQueryIsAskedAgainBeforeTheTimeout(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, Timeout: 2 * time.Second})
	var asked atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if asked.Add(1) == 1 {
			<-ctx.Done() // lost
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	t0 := time.Now()
	a := p.Resolve(context.Background(), "lost.example.org")
	took := time.Since(t0)
	if a.Status != StatusOK {
		t.Fatalf("status %s (%s)", a.Status, a.Err)
	}
	if took > time.Second {
		t.Errorf("the answer took %s: the lost query was waited out", took)
	}
	if n := asked.Load(); n != 2 {
		t.Errorf("%d queries sent, want 2", n)
	}
}

// A slow answer that comes after the next attempt was sent still counts, and
// the attempt beside it is cut.
func TestSlowFirstAnswerBeatsItsHedge(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, Timeout: time.Second})
	var asked atomic.Int32
	cut := make(chan struct{})
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if asked.Add(1) == 2 {
			<-ctx.Done()
			close(cut)
			return nil, ctx.Err()
		}
		time.Sleep(400 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	if a := p.Resolve(context.Background(), "slow.example.org"); a.Status != StatusOK {
		t.Fatalf("status %s (%s)", a.Status, a.Err)
	}
	select {
	case <-cut:
	case <-time.After(time.Second):
		t.Error("the attempt sent beside the answered one was not cut")
	}
}

// An attempt packs its query while the next one is made beside it: each has
// its own copy (with -race, a shared one is a data race).
func TestAttemptsBesideEachOtherHaveTheirOwnQuery(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, Timeout: 2 * time.Second})
	var asked atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if asked.Add(1)%2 == 1 {
			for ctx.Err() == nil { // lost, and packed again as a real exchange packs what it sends
				_, _ = q.Pack()
			}
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	for _, name := range []string{"a.example.org", "b.example.org", "c.example.org"} {
		if a := p.Resolve(context.Background(), name); a.Status != StatusOK {
			t.Fatalf("%s: status %s (%s)", name, a.Status, a.Err)
		}
	}
}

// Every attempt of a name fails: the pool tries once each (Retries+1) and says so.
func TestHedgingKeepsTheAttemptCount(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, Timeout: time.Second})
	var asked atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		asked.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	a := p.Resolve(context.Background(), "dead.example.org")
	if a.Status != StatusFailed {
		t.Errorf("status %s, want failed", a.Status)
	}
	if n := asked.Load(); n != 3 {
		t.Errorf("%d queries sent for one name, want 3 (2 retries)", n)
	}
}

// Under a pace a query waits for its slot before it is sent; that wait is
// not lateness. Names that answer at once are asked once each, and the run
// takes what the pace says (600 queries at 200 a second: 3 s), not longer
// because hedges spent slots.
func TestPacedQueriesAreNotHedgedWhileTheyWaitForASlot(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53"}, PerSecond: 200, Burst: 1, Timeout: 2 * time.Second})
	var asked atomic.Int32
	p.Exchange = slowLive(time.Millisecond, &asked)
	t0 := time.Now()
	out := p.ResolveMany(context.Background(), names(600), 128)
	took := time.Since(t0)
	for _, a := range out {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
	if n := asked.Load(); n != 600 {
		t.Errorf("%d queries for 600 names that answer at once, want 600", n)
	}
	if took > 3600*time.Millisecond {
		t.Errorf("600 queries at 200 a second took %s, want about 3 s", took)
	}
}

// Under a pace a lost query is asked again when its timeout is up, as dnsx
// asks again: an attempt beside it would spend a slot of the user's rate on
// every answer that is merely slow.
func TestPacedLostQueryIsAskedAgainAfterTheTimeout(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, PerSecond: 20, Timeout: time.Second})
	var asked atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, server string) (*dns.Msg, error) {
		if asked.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	t0 := time.Now()
	a := p.Resolve(context.Background(), "lost.example.org")
	if took := time.Since(t0); a.Status != StatusOK || took < time.Second || asked.Load() != 2 {
		t.Errorf("status %s after %s, %d queries; want ok after the 1 s timeout, 2 queries", a.Status, took, asked.Load())
	}
}

// Answers that take longer than a hedge delay but come within the timeout
// are asked once each under a pace: 100 names that answer in 600 ms cost 100
// queries, where a hedge at 250 ms made it 2 or 3 each.
func TestPacedSlowAnswersAreNotAskedTwice(t *testing.T) {
	p := New(Options{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, PerSecond: 200, Timeout: 3 * time.Second})
	var asked atomic.Int32
	p.Exchange = slowLive(600*time.Millisecond, &asked)
	for _, a := range p.ResolveMany(context.Background(), names(100), 128) {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
	if n := asked.Load(); n != 100 {
		t.Errorf("%d queries for 100 slow names, want 100", n)
	}
}

// A resolver that answers some queries and drops what is over its limit (as
// public resolvers do to a busy client) is loaded, not down: the names it
// dropped get the slower second pass and are answered.
func TestResolveManyAsksAgainWhatALoadedResolverDropped(t *testing.T) {
	p := New(Options{Timeout: 40 * time.Millisecond, Attempts: 1})
	var inflight atomic.Int32
	p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		defer inflight.Add(-1)
		if inflight.Add(1) > 40 {
			<-ctx.Done() // over the limit: dropped
			return nil, errors.New("read udp: i/o timeout")
		}
		time.Sleep(5 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	out := p.ResolveMany(context.Background(), names(400), 128)
	for _, a := range out {
		if a.Status == StatusFailed || a.Status == StatusBroken {
			t.Fatalf("a name a loaded resolver dropped was not asked again: %+v", a)
		}
	}
}

// Names a zone's dead servers never answer are not asked a second time: the
// second pass asks 16 of them first and, when none is answered, leaves the
// rest with their first failure. 100 names, 40 of them in a zone that is
// silent, cost their 3 attempts and 16 names' second pass, not 6 attempts
// each; the 60 that answer are untouched.
func TestResolveManySecondPassEndsWhenNoneOfItsFirstNamesAnswers(t *testing.T) {
	p := New(Options{Timeout: 20 * time.Millisecond})
	var asked atomic.Int32
	dead := func(name string) bool { return strings.HasPrefix(name, "d") }
	p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		asked.Add(1)
		if dead(q.Question[0].Name) {
			<-ctx.Done()
			return nil, errors.New("read udp: i/o timeout")
		}
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	var all []string
	for i := 0; i < 60; i++ {
		all = append(all, fmt.Sprintf("h%d.example.org", i))
	}
	for i := 0; i < 40; i++ {
		all = append(all, fmt.Sprintf("d%d.example.org", i))
	}
	for _, a := range p.ResolveMany(context.Background(), all, 128) {
		switch {
		case dead(a.Name) && a.Status != StatusFailed:
			t.Fatalf("%s: %s, want its failure", a.Name, a.Status)
		case !dead(a.Name) && a.Status != StatusOK:
			t.Fatalf("%s: %s %s", a.Name, a.Status, a.Err)
		}
	}
	// 60 answers, 3 attempts for each of 40 names, 3 more for 16 of them.
	if n, max := int(asked.Load()), 60+40*3+retryProbe*3; n > max {
		t.Errorf("%d queries, want at most %d: the second pass asked names that no probe name answered", n, max)
	}
}

// A second pass whose first names are answered goes on to the rest: half
// the names a resolver dropped (every other one) answer when asked again.
func TestResolveManySecondPassGoesOnWhenItsFirstNamesAnswer(t *testing.T) {
	p := New(Options{Timeout: 20 * time.Millisecond, Attempts: 1})
	var mu sync.Mutex
	seen := map[string]int{}
	p.Exchange = func(ctx context.Context, q *dns.Msg, _ string) (*dns.Msg, error) {
		name := q.Question[0].Name
		mu.Lock()
		seen[name]++
		n := seen[name]
		mu.Unlock()
		var i int
		fmt.Sscanf(strings.TrimPrefix(name, "h"), "%d", &i)
		if n == 1 && i%2 == 0 { // dropped once: answered when asked again
			<-ctx.Done()
			return nil, errors.New("read udp: i/o timeout")
		}
		m := new(dns.Msg)
		m.SetReply(q)
		rr, _ := dns.NewRR(name + " 60 IN A 192.0.2.1")
		m.Answer = append(m.Answer, rr)
		return m, nil
	}
	for _, a := range p.ResolveMany(context.Background(), names(200), 128) {
		if a.Status != StatusOK {
			t.Fatalf("%s: %s %s: a name the second pass could answer was not asked", a.Name, a.Status, a.Err)
		}
	}
}
