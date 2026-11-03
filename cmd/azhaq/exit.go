package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// The exit code of a run is decided here, from its summary, and nowhere
// else: settle calls decide. The rule is in docs/OUTPUT.md ("Exit 3").
//
//	4  a limit, the kill file or a signal stopped the work
//	0  nothing failed, or the run did its job and the summary names every failure
//	3  the run's own job failed or is incomplete (see jobFailed), or -strict-exit
//
// strictExit is -strict-exit: any failure exits 3, as before 0.15.
var strictExit bool

// strictExitUsage is the help of -strict-exit, the same for every command that has it.
const strictExitUsage = "exit 3 for any failure, a target among many included (the rule before 0.15); without it a run that did its job exits 0 and its summary counts and lists the failures"

// jobCollectors is the collector whose failure on a URL is that URL failing, for
// the commands whose job is something done to a page, not reaching it.
var jobCollectors = map[string]string{"params": "azhaq-params", "dirs": "azhaq-dirs", "shots": "azhaq-shots"}

// strictCommands are the commands that take -strict-exit: those whose summary lists failures.
var strictCommands = map[string]bool{
	"run": true, "crawl": true, "probe": true, "subs": true, "urls": true, "dns": true,
	"dirs": true, "fuzz": true, "params": true, "shots": true,
}

// flagOn says a boolean flag of fs is set.
func flagOn(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	return f != nil && f.Value.String() == "true"
}

// tally is what a command knows of the targets it was given: how many it
// could count and how many of them got no answer at all. A run whose every
// counted target failed did not do its job; one with a single answer did.
type targetTally struct{ given, failed int }

// units records the targets a command was given and how many got no answer.
func (r *report) units(given, failed int) { r.targets = targetTally{given, failed} }

// failureCount is the summary's `failures`: the sum of `count` over `failed`,
// plus each unreachable target no entry of `failed` names (a list holds at most
// 100 targets: with a longer one the unreachable are taken as named). probe
// counts its rows without an answer.
func (r *report) failureCount() int {
	if r.failedRows != nil {
		return *r.failedRows
	}
	n, named, cut := 0, map[string]bool{}, false
	for _, f := range r.Failed {
		n += f.Count
		cut = cut || len(f.Targets) >= 100
		for _, t := range f.Targets {
			named[t] = true
		}
	}
	if !cut {
		for _, u := range r.Unreachable {
			if !named[u] {
				n++
			}
		}
	}
	return n
}

// hasFailure says the run has something to say about failure at all.
func (r *report) hasFailure() bool {
	return len(r.Unreachable) > 0 || len(r.Failed) > 0 || r.Degraded || r.warned || r.failedRows != nil && *r.failedRows > 0
}

// jobFailed says the run did not do its job, or did it in part and cannot
// say which. One rule for every command: a run is done with failures when
// at least one target it was given answered and each failure is named in
// the summary; it failed when
//   - no target it was given answered (every counted URL or domain failed),
//   - a failure names no target (the run's own: a lost session, a panic, a
//     report that was not written), or is the -exec connector's, or
//   - a note says the results are short or misleading (r.warned: names cut,
//     names not checked, a dead session, a picture short of its page).
//
// A run that was given nothing it can count (an address list, a range) says
// nothing of answers, so any failure fails it, as before.
func (r *report) jobFailed() bool {
	if r.warned {
		return true
	}
	for _, f := range r.Failed {
		if ownFailure(f) {
			return true
		}
	}
	if r.targets.given == 0 || r.Degraded && len(r.Failed) == 0 {
		return true // nothing to count, or degraded and no failure names what failed
	}
	return r.targets.failed >= r.targets.given
}

// ownFailure says a failure is the run's own, not a target's: it names no
// target, it is a bug, or it is the user's -exec connector.
func ownFailure(f engine.Failure) bool {
	return len(f.Targets) == 0 || strings.HasPrefix(f.Error, guard.Prefix) || f.Collector == "connector"
}

// decide is the exit code of a run that no limit stopped.
func (r *report) decide() int {
	switch {
	case !r.hasFailure():
		return exitOK
	case strictExit || r.jobFailed():
		return exitPartial
	}
	return exitOK
}

// tallySeeds counts the targets a run was given that it can tell answered
// from failed: a URL fails when none of its requests got an answer
// (unreachable), a domain when no third-party source answered for it.
func tallySeeds(command string, seeds []types.Seed, unreachable []string, failed []engine.Failure) targetTally {
	down := map[string]bool{}
	for _, u := range unreachable {
		down[u] = true
	}
	// The collector that does the command's own work on a URL: a page it
	// could not take, sweep or screenshot is a URL that failed, answered or not.
	for _, f := range failed {
		if f.Collector == jobCollectors[command] && !f.Fanout {
			for _, t := range f.Targets {
				if u, err := normalize.URL(t); err == nil {
					down[u] = true
				}
				down[t] = true
			}
		}
	}
	silent := map[string]bool{}
	for _, f := range failed {
		if f.Partial || f.Fanout || !engine.IsThirdParty(f.Collector) {
			continue
		}
		for _, t := range f.Targets {
			silent[normalize.Hostname(t)] = true
		}
	}
	var t targetTally
	seen := map[string]bool{}
	for _, s := range seeds {
		if s = normalize.Seed(s); s.Derived() || (s.Type != types.TypeURL && s.Type != types.TypeDomain) || seen[string(s.Type)+s.Key()] {
			continue
		}
		seen[string(s.Type)+s.Key()] = true
		t.given++
		if s.Type == types.TypeURL && down[s.Key()] || s.Type == types.TypeDomain && silent[s.Key()] {
			t.failed++
		}
	}
	return t
}

// doneWith is the summary line of a run that did its job and has failures.
func (r *report) doneWith() string {
	n := r.Failures
	if n == 0 {
		n = 1
	}
	what := "failures"
	if n == 1 {
		what = "failure"
	}
	return fmt.Sprintf("the run did its job and names its %d %s", n, what)
}

// failedBecause is the summary line of a run that exits 3: the part of the rule it met.
func (r *report) failedBecause() string {
	switch {
	case strictExit && !r.jobFailed():
		return "-strict-exit: a failure exits 3 even though the run did its job; the results are usable"
	case r.warned && len(r.Unreachable) == 0 && len(r.Failed) == 0 && !r.Degraded:
		return "finished, but a note above says what to check first"
	case r.warned:
		return "the results are short or misleading (a note above says why), and what is marked ! failed"
	case r.targets.given > 0 && r.targets.failed >= r.targets.given:
		return fmt.Sprintf("nothing the run was given answered (%d of %d failed); what is marked ! failed", r.targets.failed, r.targets.given)
	}
	for _, f := range r.Failed {
		if ownFailure(f) {
			return "the run's own work failed (a failure names no target, is a bug, or is the -exec connector); what is marked ! failed"
		}
	}
	return "the targets given cannot be counted (addresses, ranges), so any failure exits 3; what is marked ! failed"
}
