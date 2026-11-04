package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// stoppedSubs is a subs run of a workspace that a limit stopped after its
// sources had answered: the names it listed that no DNS lookup has answered
// yet are kept in the workspace, and the sources need not be asked again.
type stoppedSubs struct {
	run     string // the run to continue
	pending int    // the names of its sources' payloads with no DNS answer yet
}

// stoppedSubsRun finds, in the workspace db, the run a subs command with
// these domains and -skip would continue: the newest run, started by subs, on
// the same domains and the same collectors, that has tasks left and whose
// sources have all answered (a payload for every domain) with names no
// lookup has answered. ok is false when there is none: the command then
// starts a run of its own.
func stoppedSubsRun(db string, domains []string, skip string) (s stoppedSubs, ok bool) {
	if _, err := os.Stat(db); err != nil {
		return s, false
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		return s, false
	}
	defer st.Close()
	runs, err := st.Runs()
	if err != nil || len(runs) == 0 {
		return s, false
	}
	id, args, _, resumable, err := st.Resumable()
	if err != nil || !resumable || id != runs[len(runs)-1].ID || st.GetMeta("command:"+id) != "subs" {
		return s, false
	}
	if was, _ := flagValue(args, "skip"); was != skip || !sameSet(flagValues(args, "domain"), domains) {
		return s, false
	}
	st.UseRun(id)
	answered := map[string]bool{}
	for name, p := range dnsAnswers(st) {
		answered[name] = p["degraded"] != true
	}
	heard := map[string]bool{}
	for _, p := range payloads(st, "azhaq-subdomains") {
		d, _ := p["domain"].(string)
		heard[d] = sourcesAnswered(p)
		for _, n := range strs(p["names"]) {
			if n != d && !answered[n] {
				s.pending++
			}
		}
	}
	for _, d := range domains {
		if !heard[d] {
			return s, false // its sources were cut short: they are asked again
		}
	}
	s.run = id
	if s.pending == 0 {
		return s, false
	}
	keepSubsAnswers(st, id)
	return s, true
}

// sourcesAnswered says whether a subdomains payload holds what the sources
// gave: none was cut by the run's own stop. The sources that pad their answer
// with guesses (they have the counts of a check) are not looked at: what they
// left unchecked is what a continued run checks, and more samples of their
// guesses are not asked.
func sourcesAnswered(p map[string]any) bool {
	srcs, _ := p["sources"].(map[string]any)
	for _, v := range srcs {
		row, _ := v.(map[string]any)
		if row["skipped"] != nil || row["dropped_unresolved"] != nil {
			continue
		}
		if e, _ := row["error"].(string); strings.Contains(e, types.CutShort) || strings.Contains(e, "stopped with the run") || strings.Contains(e, "(-max-time)") {
			return false
		}
	}
	return true
}

// keepSubsAnswers marks done the sources tasks of run id whose answer the
// workspace holds whole: a run the limit stopped leaves them undone, and a
// continued run would ask the sources again. It returns how many it marked.
func keepSubsAnswers(st *store.Store, id string) int {
	st.UseRun(id)
	whole := map[string]bool{}
	for _, p := range payloads(st, "azhaq-subdomains") {
		d, _ := p["domain"].(string)
		whole[d] = sourcesAnswered(p)
	}
	tasks, err := st.Tasks()
	if err != nil {
		return 0
	}
	var ids []string
	for _, t := range tasks {
		if t.Collector == "azhaq-subdomains" && !t.Done && whole[t.Seed.Key()] {
			ids = append(ids, t.ID)
		}
	}
	if len(ids) == 0 || st.SaveTasks(nil, ids, nil) != nil {
		return 0
	}
	return len(ids)
}

// flagValues are the values a repeatable flag has in args.
func flagValues(args []string, name string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		k, v, eq := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if !strings.HasPrefix(args[i], "-") || k != name {
			continue
		}
		switch {
		case eq:
			out = append(out, v)
		case i+1 < len(args):
			i++
			out = append(out, args[i])
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	a, b = slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b))
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// note is the summary's account of a run that continued one.
func (s stoppedSubs) note(db string) string {
	return fmt.Sprintf("continued the stopped run in %s: %s no DNS answer yet and were asked; the sources were not asked again (-fresh asks them again)",
		db, nOf(s.pending, "name had", "names had"))
}
