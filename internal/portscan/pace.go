package portscan

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/limit"
)

// The connect pace of a scan that was given none is adaptive, as nmap's
// timing is: it starts at DefaultRate, rises while the answers come back in
// time, and backs off when they stop. A -rate, -port-rate or -host-rate
// given is a fixed ceiling and is never passed.
const (
	// AdaptiveCeiling is the most connects a second the default pace reaches.
	AdaptiveCeiling = 20000
	// paceFloor is the least it backs off to, a given -min-rate aside.
	paceFloor = 200
	// An epoch is judged once it has this many outcomes and has lasted this
	// long: a timeout shows a wait later, so a shorter one only sees the past.
	paceEpochN   = 128
	paceEpochDur = 100 * time.Millisecond
	// paceHold is how long after a back-off its own cause is still arriving:
	// no change is made meanwhile.
	paceHold = 300 * time.Millisecond
	// A back-off takes the pace to paceBackoff of what it was. Until the first,
	// each epoch raises it by paceRise; above the rate it backed off to, by
	// paceCreep.
	paceBackoff = 0.7
	paceRise    = 1.25
	paceCreep   = 1.05
	// paceHist is how many epochs the baseline of loss and round trip spans.
	paceHist = 8
	// paceTrust is how many answers an address gives before a timeout of its
	// ports is taken for loss: one that answers nothing is filtered or down.
	paceTrust = 16
)

// pacer moves the connect rate of a scan by what the answers say.
//
//	raise:    no loss, the round trip not grown, answers keep coming, and the
//	          pace is what holds the scan back: x1.25 an epoch until the first
//	          back-off, x1.05 above the rate it backed off to
//	back off: x0.7 (not under the floor) when timeouts of an address that
//	          answers appear that its earlier epochs did not have, or the
//	          round trip passes three times its baseline
//
// A refused port, an unreachable one and a timeout of an address that has
// answered little are not loss: a firewall times out at any pace. Loss is a
// rise over the baseline of the last epochs, so a host that times out a steady
// share of its ports (a filter) does not hold the pace down.
type pacer struct {
	lim                *limit.Limiter
	floor, ceil, start float64
	now                func() time.Time

	mu       sync.Mutex
	rate     float64
	thresh   float64 // above it the pace is raised slowly (0: not yet backed off)
	t0       time.Time
	n, ans   int // outcomes of the epoch, and the answered ones
	lost     int
	rttN     int
	rttSum   time.Duration
	loss     [paceHist]float64
	rtt      [paceHist]time.Duration
	hist     int // epochs kept
	hold     time.Time
	backoffs int
	peak     float64
}

func newPacer(start, floor, ceil float64) *pacer {
	floor = min(max(floor, 1), start)
	ceil = max(ceil, start)
	p := &pacer{start: start, floor: floor, ceil: ceil, rate: start, peak: start, now: time.Now}
	p.lim = limit.New(start, paceBurst(start))
	return p
}

// paceBurst is the connects the limiter lets through at once: a batch (32 at
// most) must fit it.
func paceBurst(rate float64) int { return max(int(rate/10), 32) }

// Rate is the pace now.
func (p *pacer) Rate() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rate
}

// Backoffs is how many times the pace has backed off.
func (p *pacer) Backoffs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.backoffs
}

type outcome int

const (
	answered   outcome = iota // accepted or refused, with its round trip
	timedOut                  // no answer in the wait
	unanswered                // an error at once (unreachable), the kill file, the scope
)

// note counts one finished connect. lost says a timeout counts as loss.
func (p *pacer) note(o outcome, rtt time.Duration, lost bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.t0.IsZero() {
		p.t0 = now
	}
	p.n++
	switch o {
	case answered:
		p.ans++
		if rtt > 0 {
			p.rttN++
			p.rttSum += rtt
		}
	case timedOut:
		if lost {
			p.lost++
		}
	}
	if p.n >= paceEpochN && now.Sub(p.t0) >= paceEpochDur {
		p.roll(now)
	}
}

// roll judges the epoch that ends now (the caller holds mu).
func (p *pacer) roll(now time.Time) {
	dur := now.Sub(p.t0)
	n, ans, lost, rttN := p.n, p.ans, p.lost, p.rttN
	var rtt time.Duration
	if rttN > 0 {
		rtt = p.rttSum / time.Duration(rttN)
	}
	p.t0, p.n, p.ans, p.lost, p.rttN, p.rttSum = now, 0, 0, 0, 0, 0
	var frac float64
	if ans+lost > 0 {
		frac = float64(lost) / float64(ans+lost)
	}
	baseLoss, baseRTT, known := p.baseline()
	if ans+lost >= 32 {
		p.push(frac, rtt)
	}
	if now.Before(p.hold) {
		return
	}
	// Loss is a rise over what the epochs before it showed, past what chance
	// does to a sample of this size.
	slack := max(0.03, 4*math.Sqrt(baseLoss*(1-baseLoss)/float64(max(ans+lost, 1))))
	lossy := known && lost >= 3 && frac > baseLoss+slack
	grown := known && rttN >= 8 && baseRTT > 0 && rtt > 3*baseRTT+10*time.Millisecond
	switch {
	case lossy || grown:
		p.set(max(p.floor, p.rate*paceBackoff))
		p.thresh = p.rate
		p.hold = now.Add(paceHold)
		p.backoffs++
	case p.rate < p.ceil && ans >= max(16, n/8) && float64(n) >= 0.6*p.rate*dur.Seconds():
		g := paceRise
		if p.thresh > 0 && p.rate >= p.thresh {
			g = paceCreep
		}
		p.set(min(p.ceil, p.rate*g))
	}
}

// baseline is the least loss and round trip of the epochs kept; known says
// enough epochs (two) are kept to judge by.
func (p *pacer) baseline() (loss float64, rtt time.Duration, known bool) {
	k := min(p.hist, paceHist)
	loss = 1
	for i := 0; i < k; i++ {
		loss = min(loss, p.loss[i])
		if r := p.rtt[i]; r > 0 && (rtt == 0 || r < rtt) {
			rtt = r
		}
	}
	if k == 0 {
		loss = 0
	}
	return loss, rtt, k >= 2
}

func (p *pacer) push(loss float64, rtt time.Duration) {
	i := p.hist % paceHist
	p.loss[i], p.rtt[i] = loss, rtt
	p.hist++
}

func (p *pacer) set(r float64) {
	p.rate = r
	p.peak = max(p.peak, r)
	p.lim.Tune("", r, paceBurst(r))
}

// passPace is what one pass over an address tells its scanner's pacer. A nil
// one tells nothing (the pace is fixed, or loopback is not paced).
type passPace struct {
	p    *pacer
	feed bool         // what it sees moves the pace
	ans  atomic.Int32 // the address's answers so far
}

func (pp *passPace) answered(rtt time.Duration) {
	if pp != nil {
		pp.ans.Add(1)
		if pp.feed {
			pp.p.note(answered, rtt, false)
		}
	}
}

// timedOut is a connect that got no answer in its wait; it says whether the
// address had been answering, so that the timeout counts as loss.
func (pp *passPace) timedOut() bool {
	if pp == nil {
		return false
	}
	lost := pp.ans.Load() >= paceTrust
	if pp.feed {
		pp.p.note(timedOut, 0, lost)
	}
	return lost
}

func (pp *passPace) unanswered() {
	if pp != nil && pp.feed {
		pp.p.note(unanswered, 0, false)
	}
}
