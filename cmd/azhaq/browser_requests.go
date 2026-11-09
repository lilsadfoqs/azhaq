package main

import (
	"fmt"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// browserRequests is what became of the requests Chrome was asked to send in
// a command: Sent are the ledger's Chrome lines, each answered (a response or a
// redirect) or not by the time its page was read or Chrome closed, and
// Blocked are the requests it was not let send (outside the scope, over the
// budget, held by a -deny-path rule or as a state change, a write mapped and
// not sent). Answered plus Unanswered is Sent.
type browserRequests struct {
	Sent       int `json:"sent"`
	Answered   int `json:"answered"`
	Unanswered int `json:"unanswered"`
	Blocked    int `json:"blocked"`
}

func (b *browserRequests) line() string {
	return fmt.Sprintf("browser requests: %d sent, %d answered, %d unanswered, %d blocked by scope or held", b.Sent, b.Answered, b.Unanswered, b.Blocked)
}

// browserRequestsSince is the command's own, from the snapshots taken when it
// began; nil when Chrome sent and refused nothing.
func browserRequestsSince(from map[ledger.SpentKey]int64, at ledger.ChromeTally) *browserRequests {
	now := ledger.ChromeOutcomes()
	b := &browserRequests{Sent: ledger.ChromeSent(accountSince(from)), Blocked: int(now.Blocked - at.Blocked)}
	b.Answered = min(int(now.Answered-at.Answered), b.Sent)
	b.Unanswered = b.Sent - b.Answered
	if b.Sent == 0 && b.Blocked == 0 {
		return nil
	}
	return b
}
