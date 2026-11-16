package egress

import (
	"testing"
	"time"
)

func TestRTTWaitFollowsTheAnswers(t *testing.T) {
	const limit = 1500 * time.Millisecond
	var m rttModel
	for i := 0; i < rttSamples-1; i++ {
		m.add(30 * time.Microsecond)
	}
	if got := m.wait(limit); got != limit {
		t.Errorf("before %d answers the wait is %s, want the timeout", rttSamples, got)
	}
	m.add(30 * time.Microsecond)
	if got := m.wait(limit); got != rttFloor {
		t.Errorf("a quick host is waited for %s, want the floor %s", got, rttFloor)
	}
	var slow rttModel
	for i := 0; i < 2*rttSamples; i++ {
		slow.add(400 * time.Millisecond)
	}
	if got := slow.wait(limit); got <= rttFloor || got > limit {
		t.Errorf("a host that answers in 400 ms is waited for %s", got)
	}
	var far rttModel
	for i := 0; i < 2*rttSamples; i++ {
		far.add(2 * time.Second)
	}
	if got := far.wait(limit); got != limit {
		t.Errorf("the wait is %s, never over the timeout %s", got, limit)
	}
}

// A dialer that was not asked to adapt keeps its timeout.
func TestPortDialerKeepsItsTimeoutUnlessAdapted(t *testing.T) {
	d := NewPortDialer(time.Second, nil, "", "")
	if d.model("127.0.0.1") != nil {
		t.Error("a dialer has a round trip model before Adapt")
	}
	d.Adapt()
	if d.model("127.0.0.1") == nil {
		t.Error("an adapted dialer has none")
	}
	p := NewPortDialer(time.Second, nil, "127.0.0.1:1", "")
	p.Adapt()
	if p.model("127.0.0.1") != nil {
		t.Error("a proxied dialer follows the proxy's round trip")
	}
}
