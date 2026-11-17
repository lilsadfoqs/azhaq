package egress

import (
	"sync"
	"time"
)

// rttModel is what the answers of one address say of its round trip, kept as
// TCP's retransmit timer keeps it (RFC 6298; nmap's timing does the same): a
// port that stays silent is then given up on after a few round trips, not
// after the whole connect timeout, which a wedged listener on a quick host
// would cost the scan in full.
type rttModel struct {
	mu           sync.Mutex
	n            int
	srtt, rttvar float64 // seconds
}

const (
	// rttSamples is how many answers an address gives before its wait is cut.
	rttSamples = 16
	// rttFloor is the least a silent port is waited for: a host's answers can
	// come later than its average, and the pass over the silent ports follows.
	rttFloor = 250 * time.Millisecond
	// rttRecheckMs is how often a batch that waits looks again at the wait.
	rttRecheckMs = 25
)

func (m *rttModel) add(d time.Duration) {
	r := d.Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n == 0 {
		m.srtt, m.rttvar = r, r/2
	} else {
		diff := m.srtt - r
		if diff < 0 {
			diff = -diff
		}
		m.rttvar = 0.75*m.rttvar + 0.25*diff
		m.srtt = 0.875*m.srtt + 0.125*r
	}
	m.n++
}

// wait is how long to wait for one answer, at most max.
func (m *rttModel) wait(limit time.Duration) time.Duration {
	m.mu.Lock()
	n, rto := m.n, time.Duration((m.srtt+4*m.rttvar)*float64(time.Second))
	m.mu.Unlock()
	if n < rttSamples {
		return limit
	}
	return min(limit, max(rto, rttFloor))
}

// Adapt makes the wait of a connect follow the round trip its address
// answers in, up to the dialer's timeout. A proxied scan keeps the timeout:
// the round trip is the proxy's.
func (d *PortDialer) Adapt() { d.adapt = d.via == nil && d.socks == "" }

// model is the round trip model of ip (nil: the wait is the timeout).
func (d *PortDialer) model(ip string) *rttModel {
	if !d.adapt {
		return nil
	}
	if m, ok := d.rtts.Load(ip); ok {
		return m.(*rttModel)
	}
	m, _ := d.rtts.LoadOrStore(ip, &rttModel{})
	return m.(*rttModel)
}

// SimulateLoss makes the batched connects of d for which drop is true go
// unanswered, as a SYN lost on the way is: a stand-in for a lossy path in
// tests, which loopback cannot give. Set it before the scan.
func (d *PortDialer) SimulateLoss(drop func(ip string, port int) bool) { d.loss = drop }
