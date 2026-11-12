package main

import (
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/store"
)

// pickRun is the run of a workspace that -run (the run_id of a summary, or
// the start of one) names, or the newest when none is named.
func pickRun(runs []store.Run, want string) (store.Run, error) {
	if len(runs) == 0 {
		return store.Run{}, fmt.Errorf("the workspace holds no run")
	}
	if want == "" {
		return runs[len(runs)-1], nil
	}
	var hit []store.Run
	for _, r := range runs {
		if r.ID == want {
			return r, nil
		}
		if len(want) >= 4 && strings.HasPrefix(r.ID, want) {
			hit = append(hit, r)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return store.Run{}, usagef("-run %s: no such run in the workspace (a summary's run_id names one; azhaq query -db FILE -runs lists them)", want)
	}
	return store.Run{}, usagef("-run %s starts %d runs: give more of the id", want, len(hit))
}

// runFailures is what one run of a workspace left failed.
type runFailures struct {
	Run       string
	Failed    int // failed targets
	Retryable int // those a later try may fix
}

// failuresOf reads the failed targets of one run.
func failuresOf(st *store.Store, run string) ([]engine.FailedTarget, error) {
	st.UseRun(run)
	ents, err := st.Entities()
	if err != nil {
		return nil, err
	}
	obs, err := st.Observations()
	if err != nil {
		return nil, err
	}
	return append(engine.FailedTargets(ents, obs), storedSweeps(st, run)...), nil
}

// earlierFailures are the runs of the workspace other than skip that left
// failed targets, newest first.
func earlierFailures(st *store.Store, runs []store.Run, skip string) []runFailures {
	var out []runFailures
	for i := len(runs) - 1; i >= 0; i-- {
		if runs[i].ID == skip {
			continue
		}
		list, err := failuresOf(st, runs[i].ID)
		if err != nil || len(list) == 0 {
			continue
		}
		rf := runFailures{Run: runs[i].ID, Failed: len(list)}
		fuzzed := isFuzzRun(st) // st.UseRun(runs[i].ID) was called by failuresOf
		for _, f := range list {
			if f.Retryable && !fuzzed {
				rf.Retryable++
			}
		}
		out = append(out, rf)
	}
	return out
}

// otherRunsNote names the runs that have failed targets when the one read
// has none, with the command that reads or retries each; at most three.
func otherRunsNote(db string, runs []runFailures, retry bool) string {
	var parts []string
	for i, r := range runs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more runs", len(runs)-3))
			break
		}
		if retry {
			if r.Retryable == 0 {
				continue
			}
			parts = append(parts, fmt.Sprintf("run %s has %s: azhaq resume -db %s -retry-failed -retry-run %s", r.Run, plural(r.Retryable, "retryable failed target"), db, r.Run))
			continue
		}
		parts = append(parts, fmt.Sprintf("run %s has %s: azhaq query -db %s -failed -run %s", r.Run, plural(r.Failed, "failed target"), db, r.Run))
	}
	return strings.Join(parts, "; ")
}
