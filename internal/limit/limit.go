// Package limit paces requests per key: a target host, a third-party
// source, a DNS resolver. One Limiter is shared by everything that talks
// to the same kind of endpoint in a run.
package limit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// windowMargin is added to the second a strict Limiter holds: a send
// stamped a little after its slot must not let the next one in less than
// a second after it.
const windowMargin = 2 * time.Millisecond

// Limiter is a set of token buckets, one per key, created on first use.
// A zero or negative rate means no limit.
type Limiter struct {
	mu        sync.Mutex
	perSecond float64
	burst     int
	overrides map[string]float64
	buckets   map[string]*rate.Limiter
	strict    bool
	rings     map[string]*ring
}

// ring holds the times of a key's last sends, for a strict Limiter.
type ring struct {
	mu sync.Mutex
	n  int
	ts []time.Time
}

// New returns a Limiter allowing perSecond requests per key with the given
// burst.
func New(perSecond float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		perSecond: perSecond,
		burst:     burst,
		overrides: map[string]float64{},
		buckets:   map[string]*rate.Limiter{},
		rings:     map[string]*ring{},
	}
}

// Strict makes Wait hold each key to its rate in every window of one
// second: a bucket alone lets a wake-up that ran late and the next one on
// time land less than a second apart, one send over the rate. Returns l.
func (l *Limiter) Strict() *Limiter {
	l.mu.Lock()
	l.strict = true
	l.mu.Unlock()
	return l
}

// Set gives one key its own rate. It applies to buckets created after the
// call and to an existing bucket for that key.
func (l *Limiter) Set(key string, perSecond float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.overrides[key] = perSecond
	if b, ok := l.buckets[key]; ok {
		b.SetLimit(toLimit(perSecond))
	}
}

// Wait blocks until key may send one request or ctx ends.
func (l *Limiter) Wait(ctx context.Context, key string) error {
	if l == nil {
		return ctx.Err()
	}
	if err := Wait(ctx, l.bucket(key)); err != nil {
		return err
	}
	return l.slide(ctx, key)
}

// slide waits until the key has sent fewer than its rate in the last second
// (a strict Limiter only), and counts this send.
func (l *Limiter) slide(ctx context.Context, key string) error {
	rg := l.ring(key)
	if rg == nil {
		return nil
	}
	for {
		rg.mu.Lock()
		now := time.Now()
		for len(rg.ts) > 0 && !rg.ts[0].Add(time.Second+windowMargin).After(now) {
			rg.ts = rg.ts[1:]
		}
		if len(rg.ts) < rg.n {
			rg.ts = append(rg.ts, now)
			rg.mu.Unlock()
			return nil
		}
		d := rg.ts[0].Add(time.Second + windowMargin).Sub(now)
		rg.mu.Unlock()
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < d {
			<-ctx.Done()
			return ctx.Err()
		}
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ring is the key's send times, nil when the Limiter is not strict or the
// key has no rate.
func (l *Limiter) ring(key string) *ring {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.strict {
		return nil
	}
	r := l.perSecond
	if o, ok := l.overrides[key]; ok {
		r = o
	}
	if r <= 0 {
		return nil
	}
	rg, ok := l.rings[key]
	if !ok {
		rg = &ring{}
		l.rings[key] = rg
	}
	rg.n = max(1, int(r))
	return rg
}

// WaitN blocks until key may send n requests at once (n at most the burst).
func (l *Limiter) WaitN(ctx context.Context, key string, n int) error {
	if l == nil {
		return ctx.Err()
	}
	b := l.bucket(key)
	n = min(n, b.Burst())
	err := b.WaitN(ctx, n)
	if err != nil && ctx.Err() == nil {
		if _, ok := ctx.Deadline(); ok {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	return err
}

// Wait is lim.Wait, but a wait that would pass ctx's deadline lasts until
// the deadline and returns ctx's error: rate refuses at once without
// ending ctx, which made a sweep stop early and look finished.
func Wait(ctx context.Context, lim *rate.Limiter) error {
	err := lim.Wait(ctx)
	if err != nil && ctx.Err() == nil {
		if _, ok := ctx.Deadline(); ok {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	return err
}

func (l *Limiter) bucket(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok {
		return b
	}
	r := l.perSecond
	if o, ok := l.overrides[key]; ok {
		r = o
	}
	b := rate.NewLimiter(toLimit(r), l.burst)
	l.buckets[key] = b
	return b
}

func toLimit(perSecond float64) rate.Limit {
	if perSecond <= 0 {
		return rate.Inf
	}
	return rate.Limit(perSecond)
}
