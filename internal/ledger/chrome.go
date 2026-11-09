package ledger

import "sync/atomic"

// What became of the requests Chrome was asked to send, beside the ledger's
// lines of the ones it sent (SpentKey kind "chrome"): each line was answered
// or was not, and the requests never sent were refused. The counts are kept
// with or without a ledger.
var chromeAnswered, chromeBlocked atomic.Int64

// ChromeAnswered counts n requests of the ledger's Chrome lines that got an
// answer: a response, or a redirect.
func ChromeAnswered(n int) { chromeAnswered.Add(int64(n)) }

// ChromeBlocked counts n requests Chrome was not let send: outside the scope,
// over the budget, held by a -deny-path rule or as a state change, or a write
// that is mapped and not sent.
func ChromeBlocked(n int) { chromeBlocked.Add(int64(n)) }

// ChromeTally is the process's count so far; two snapshots give a command's.
type ChromeTally struct{ Answered, Blocked int64 }

// ChromeOutcomes is what became of Chrome's requests so far.
func ChromeOutcomes() ChromeTally {
	return ChromeTally{chromeAnswered.Load(), chromeBlocked.Load()}
}

// ChromeSent is the number of Chrome lines to targets in an account (see
// Account): the requests Chrome sent.
func ChromeSent(acc map[SpentKey]int64) int {
	n := int64(0)
	for k, v := range acc {
		if k.Kind == "chrome" && k.Class == ClassTarget {
			n += v
		}
	}
	return int(n)
}
