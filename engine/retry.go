package engine

import (
	"sort"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// Retry is what asking the failed targets again did: Targets is how many
// failed targets (one for each collector and target) were made to run
// again, Tasks how many tasks that is, and Asked the targets themselves.
type Retry struct {
	Targets int
	Tasks   int
	Asked   []FailedTarget
}

// RetryFailed makes the current run of st ask again what failed in a way a
// later try may fix (Retryable): the task of each such failure is not done
// again, with the error it recorded dropped and the answer it kept, for a
// 429 or a 5xx from the target, forgotten, so that azhaq resume sends the
// request. A failure no task of the run covers gets one. Failures that are
// not retryable stay as they are.
func RetryFailed(st *store.Store, ents []types.Entity, obs []types.StoredObservation) (Retry, error) {
	var r Retry
	byID := map[string]types.Entity{}
	for _, e := range ents {
		byID[e.ID] = e
	}
	type key struct{ collector, entity string }
	seen := map[key]bool{}
	var tasks []store.Task
	var ids []string
	var firstErr error
	eachFailure(ents, obs, func(collector, source, raw, target, entity string) {
		if !Retryable(raw) {
			return
		}
		msg := ShortError(raw)
		if target != "" {
			r.Asked = append(r.Asked, FailedTarget{Target: target, Collector: collector, Source: source, Error: msg, Retryable: true})
			if err := st.DropResponse(target); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		k := key{collector, entity}
		e, ok := byID[entity]
		if !ok || seen[k] {
			return
		}
		seen[k] = true
		id := retryTaskID(collector, e)
		reopened, err := st.ReopenTask(id)
		if err == nil {
			err = st.DropErrors(entity, collector)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if !reopened {
			if seed, ok := seedOfEntity(e); ok {
				tasks = append(tasks, store.Task{ID: id, Collector: collector, Seed: seed})
			}
		}
		ids = append(ids, id)
	})
	if firstErr != nil {
		return r, firstErr
	}
	if err := st.SaveTasks(tasks, nil, nil); err != nil {
		return r, err
	}
	if err := st.Forget(ids); err != nil {
		return r, err
	}
	r.Tasks = len(ids)
	sort.SliceStable(r.Asked, func(i, j int) bool { return r.Asked[i].Target < r.Asked[j].Target })
	r.Asked = dedupeTargets(r.Asked)
	r.Targets = len(r.Asked)
	return r, nil
}

// retryTaskID is the id of the task of collector on the entity, as the
// scheduler records it.
func retryTaskID(collector string, e types.Entity) string {
	return taskHash(collector, e.Type, e.Key)
}

// seedOfEntity is the seed an entity stands for, for the kinds of entity
// a collector's task is made for.
func seedOfEntity(e types.Entity) (types.Seed, bool) {
	keys := map[types.SeedType]string{types.TypeURL: "url", types.TypeHostname: "fqdn", types.TypeDomain: "domain", types.TypeIPAddress: "ip", types.TypePrefix: "prefix", types.TypeASN: "asn"}
	k, ok := keys[e.Type]
	if !ok {
		return types.Seed{}, false
	}
	return types.Seed{Type: e.Type, Keys: map[string]string{k: e.Key}}, true
}

func dedupeTargets(in []FailedTarget) []FailedTarget {
	seen := map[FailedTarget]bool{}
	out := in[:0]
	for _, f := range in {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// RetryableTargets counts the failed targets of obs that a later try may
// fix: what RetryFailed would ask again.
func RetryableTargets(ents []types.Entity, obs []types.StoredObservation) int {
	n := 0
	for _, f := range FailedTargets(ents, obs) {
		if f.Retryable {
			n++
		}
	}
	return n
}
