package portscan

import (
	"testing"
	"time"
)

// clocked is a pacer on a clock the test moves.
type clocked struct {
	*pacer
	at time.Time
}

func newClocked(start, floor, ceil float64) *clocked {
	c := &clocked{at: time.Unix(1000, 0)}
	c.pacer = newPacer(start, floor, ceil)
	c.pacer.now = func() time.Time { return c.at }
	return c
}

// epoch plays 100 ms at the pace it has: lost timeouts of an address that
// answers, the other connects answered in rtt.
func (c *clocked) epoch(lost int, rtt time.Duration) { c.play(lost, rtt, true) }

// play is epoch where the timeouts are of an address that has answered
// (trusted) or one that has answered nothing.
func (c *clocked) play(lost int, rtt time.Duration, trusted bool) {
	n := max(int(c.Rate()*0.11), 128)
	pp := &passPace{p: c.pacer, feed: true}
	pp.ans.Store(paceTrust)
	dead := &passPace{p: c.pacer, feed: true}
	if trusted {
		dead = pp
	}
	for i := 0; i < n; i++ {
		c.at = c.at.Add(100 * time.Millisecond / time.Duration(n))
		if i < lost {
			dead.timedOut()
		} else {
			pp.answered(rtt)
		}
	}
	c.at = c.at.Add(time.Millisecond)
	pp.answered(rtt) // the note that closes the epoch
}

func (c *clocked) clean(epochs int) {
	for i := 0; i < epochs; i++ {
		c.epoch(0, time.Millisecond)
	}
}

// The pace rises while the answers come back in time, up to its ceiling.
func TestPaceRisesWhileAnswersComeBack(t *testing.T) {
	c := newClocked(1500, 200, 20000)
	prev := c.Rate()
	for i := 0; i < 5; i++ {
		c.clean(1)
		if r := c.Rate(); r <= prev {
			t.Fatalf("epoch %d: pace %g did not rise from %g with every answer on time", i, r, prev)
		}
		prev = c.Rate()
	}
	c.clean(30)
	if r := c.Rate(); r != 20000 {
		t.Errorf("after 35 clean epochs the pace is %g, want the ceiling 20000", r)
	}
	if c.Backoffs() != 0 {
		t.Errorf("%d back-offs with no loss", c.Backoffs())
	}
}

// Timeouts of an address that answers, new since the epochs before, take the
// pace down to 70%; the epochs that follow while the cause is still arriving
// change nothing; it never goes under the floor.
func TestPaceBacksOffOnLoss(t *testing.T) {
	c := newClocked(1500, 200, 20000)
	c.clean(4)
	high := c.Rate()
	c.epoch(int(high*0.11/10), time.Millisecond) // 10% of the connects time out
	if got, want := c.Rate(), high*paceBackoff; got != want {
		t.Fatalf("pace %g after loss, want %g", got, want)
	}
	low := c.Rate()
	c.epoch(int(low*0.11/10), time.Millisecond)
	c.clean(1)
	if c.Rate() != low || c.Backoffs() != 1 {
		t.Errorf("pace %g after %d back-offs inside the hold, want %g and 1", c.Rate(), c.Backoffs(), low)
	}
	// A path that carries 600 connects a second: what is over it is lost.
	// The pace comes down to it, and not under it.
	for i := 0; i < 30; i++ {
		c.epoch(max(int(c.Rate()*0.11)-60, 0), time.Millisecond)
	}
	if r := c.Rate(); r > 1200 || r < 200 {
		t.Errorf("pace %g on a path that carries 600, want it brought to about that", r)
	}
	c.clean(100) // and rises again, to the ceiling, once the loss stops
	if r := c.Rate(); r <= 1200 {
		t.Errorf("pace %g did not recover", r)
	}
	f := newClocked(400, 300, 20000) // a floor
	f.clean(3)
	f.epoch(50, time.Millisecond)
	if f.Backoffs() == 0 || f.Rate() < 300 {
		t.Errorf("pace %g after %d back-offs, want one, not under the floor 300", f.Rate(), f.Backoffs())
	}
}

// A round trip that grows backs the pace off as loss does: the queue is filling.
func TestPaceBacksOffWhenTheRoundTripGrows(t *testing.T) {
	c := newClocked(1500, 200, 20000)
	c.clean(4)
	high := c.Rate()
	c.epoch(0, 80*time.Millisecond)
	if c.Rate() != high*paceBackoff {
		t.Errorf("pace %g after the round trip went from 1 to 80 ms, want %g", c.Rate(), high*paceBackoff)
	}
}

// A refused port, an unreachable one and the timeouts of an address that has
// answered nothing are no loss: a firewall times out at any pace. A filter
// that times out a steady share of an address's ports holds nothing down.
func TestPaceTakesNoFilterForLoss(t *testing.T) {
	c := newClocked(1500, 200, 20000)
	pp := &passPace{p: c.pacer, feed: true} // an address that answered nothing
	for i := 0; i < 3000; i++ {
		c.at = c.at.Add(time.Millisecond)
		if i%2 == 0 {
			pp.timedOut()
		} else {
			pp.unanswered()
		}
	}
	if c.Backoffs() != 0 || c.Rate() != 1500 {
		t.Errorf("pace %g, %d back-offs for an address that never answered", c.Rate(), c.Backoffs())
	}
	// An address that answers nothing starts to time out beside the others'
	// answers: it is down or filtered, not a path that loses.
	c = newClocked(1500, 200, 20000)
	c.clean(4)
	c.play(int(c.Rate()*0.11/3), time.Millisecond, false)
	if c.Backoffs() != 0 {
		t.Error("a dead address's timeouts backed the pace off")
	}
	// An address that answers half its ports and filters the rest, at a steady share.
	c = newClocked(1500, 200, 20000)
	for i := 0; i < 30; i++ {
		c.epoch(int(c.Rate()*0.11/2), time.Millisecond)
	}
	if c.Backoffs() != 0 {
		t.Errorf("%d back-offs for a steady share of timeouts", c.Backoffs())
	}
}

// The ceiling given, and the floor, hold; and a scan with a rate of its own
// has no adaptive pace at all.
func TestPaceNeverPassesAUserCap(t *testing.T) {
	c := newClocked(1500, 200, 4000)
	c.clean(40)
	if r := c.Rate(); r != 4000 {
		t.Errorf("pace %g with a ceiling of 4000", r)
	}
	if r := newPacer(1500, 200, 100).ceil; r != 1500 {
		t.Errorf("ceiling %g under the start", r)
	}
	for _, s := range []*Scanner{{Rate: 1000}, {Rate: 50000}, {Rate: 3, Ceiling: 9000}, {Proxy: "127.0.0.1:1"}} {
		s.init()
		if s.pacer != nil {
			t.Errorf("Rate %g, proxy %q: the pace is adaptive", s.Rate, s.Proxy)
		}
	}
	s := &Scanner{Ceiling: 3000, MinRate: 600}
	s.init()
	if s.pacer == nil || s.pacer.ceil != 3000 || s.pacer.floor != 600 || s.pacer.start != DefaultRate {
		t.Errorf("adaptive pace %+v, want 1500 from 600 up to 3000", s.pacer)
	}
}

// The default pace batches its connects as at its ceiling, since it rises to
// it; a given rate batches by itself.
func TestBatchOfTheAdaptivePaceFollowsItsCeiling(t *testing.T) {
	for _, c := range []struct {
		s    *Scanner
		want int
	}{{&Scanner{}, 32}, {&Scanner{Ceiling: 3000}, 6}, {&Scanner{Ceiling: 100}, 3}, {&Scanner{Rate: 800}, 1}, {&Scanner{Rate: 5000}, 10}} {
		c.s.init()
		if got := c.s.batch(); got != c.want {
			t.Errorf("Rate %g Ceiling %g: batch %d, want %d", c.s.Rate, c.s.Ceiling, got, c.want)
		}
	}
}
