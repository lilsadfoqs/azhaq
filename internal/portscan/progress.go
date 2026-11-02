package portscan

import (
	"context"
	"sync"
	"time"
)

// Progress is what a scan of one address has finished while it goes: the
// ports asked, all those before the first connect still on its way, whose
// answer is final (open, or not open: a port that timed out, or whose
// greeting is awaited a second time, is left out, so a resume asks it
// again), and the open ones among them.
type Progress struct {
	Asked []int
	Open  []Open
}

type progressKey struct{}

// WithProgress has a scan made with ctx call fn about every second, and once
// at the end of its first pass, with what it has finished, from a goroutine of
// its own. A scan that ends before the first second never calls it.
func WithProgress(ctx context.Context, fn func(Progress)) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

// Answer states of a port in a progress.
const (
	pending uint8 = iota
	final         // refused or accepted: asked
	unsure        // timed out, a greeting to wait for again, or cut off: ask again
)

// progress keeps, by index into the pass's ports, what each answered.
type progress struct {
	fn    func(Progress)
	ports []int
	state []uint8
	opens map[int]Open
	sent  int // ports the last call had
	did   bool
}

// done notes the answer of port i; the caller holds the pass's lock.
func (p *progress) done(i int, state portState, o Open, cancelled bool) {
	switch {
	case cancelled, state == portSilent, state == portTimedOut, state == portOpen && o.again:
		p.state[i] = unsure
	default:
		p.state[i] = final
		if state == portOpen {
			p.opens[i] = o
		}
	}
}

// snapshot is the finished prefix of the ports asked so far; the caller holds the lock.
func (p *progress) snapshot(asked int) Progress {
	var out Progress
	for i := 0; i < asked && i < len(p.state); i++ {
		switch p.state[i] {
		case pending:
			return out
		case final:
			out.Asked = append(out.Asked, p.ports[i])
			if o, ok := p.opens[i]; ok {
				out.Open = append(out.Open, o)
			}
		}
	}
	return out
}

// every calls fn on a timer, slower as the lists it carries grow (a list of
// ports asked in a random order is long) until the stop func it returns is
// called, which waits for a call in progress.
func (p *progress) every(mu *sync.Mutex, asked func() int) (stop func()) {
	quit, ended := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ended)
		wait := time.Second
		for {
			t := time.NewTimer(wait)
			select {
			case <-quit:
				t.Stop()
				return
			case <-t.C:
			}
			mu.Lock()
			snap := p.snapshot(asked())
			mu.Unlock()
			if len(snap.Asked) > p.sent {
				p.call(snap)
				wait = min(max(time.Second, time.Duration(len(snap.Asked)/2000)*time.Second), 30*time.Second)
			}
		}
	}()
	return func() { close(quit); <-ended }
}

func (p *progress) call(snap Progress) {
	p.sent, p.did = len(snap.Asked), true
	p.fn(snap)
}

// last gives the end of the pass, when a call was made before it (a scan
// that was long enough to be cut off in the middle of its retries).
func (p *progress) last(mu *sync.Mutex, asked int) {
	if !p.did {
		return
	}
	mu.Lock()
	snap := p.snapshot(asked)
	mu.Unlock()
	if len(snap.Asked) > p.sent {
		p.call(snap)
	}
}
