package main

import (
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// fuzzFailKey is one failed target and the class of its error.
type fuzzFailKey struct{ origin, class string }

// fuzzFail is what the requests of one target and class did: how many, and
// the first error text.
type fuzzFail struct {
	count int
	first string
}

// fuzzFailures tallies the requests that failed after their second try, by
// target (scheme, host and port) and class of error (connection refused,
// timeout, TLS, reset, no such host, ...), keeping the first error text of each.
type fuzzFailures struct {
	mu sync.Mutex
	by map[fuzzFailKey]*fuzzFail
}

var quotedText = lazyre.New(`"[^"]*"`)

// add is the engine's OnError.
func (t *fuzzFailures) add(req *fuzz.Request, err error) {
	origin := ""
	if u, perr := url.Parse(req.URL); perr == nil && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	class := engine.ShortError(err.Error())
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.by == nil {
		t.by = map[fuzzFailKey]*fuzzFail{}
	}
	k := fuzzFailKey{origin, class}
	f := t.by[k]
	if f == nil {
		// The URL the error quotes is dropped: it holds the input and may hold a token.
		f = &fuzzFail{first: quotedText.ReplaceAllString(err.Error(), `"…"`)}
		t.by[k] = f
	}
	f.count++
}

// keys are the target and class pairs, the most failed first.
func (t *fuzzFailures) keys() []fuzzFailKey {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]fuzzFailKey, 0, len(t.by))
	for k := range t.by {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := t.by[out[i]].count, t.by[out[j]].count; a != b {
			return a > b
		}
		if out[i].class != out[j].class {
			return out[i].class < out[j].class
		}
		return out[i].origin < out[j].origin
	})
	return out
}

// failed is the summary's failed list: one entry for each class, with the
// requests it counts, the targets they went to and whether a later try may
// fix it (engine.Retryable, as query -failed says).
func (t *fuzzFailures) failed() []engine.Failure {
	var out []engine.Failure
	idx := map[string]int{}
	for _, k := range t.keys() {
		f := t.by[k]
		i, ok := idx[k.class]
		if !ok {
			i = len(out)
			idx[k.class] = i
			out = append(out, engine.Failure{Collector: "azhaq-fuzz", Error: k.class, Retryable: engine.Retryable(f.first)})
		}
		out[i].Count += f.count
		if h := normalize.HostFromURL(k.origin); h != "" && !slices.Contains(out[i].Targets, h) {
			out[i].Targets = append(out[i].Targets, h)
		}
	}
	return out
}

// firstText is the first error text of a class, over its targets.
func (t *fuzzFailures) firstText(class string) string {
	for _, k := range t.keys() {
		if k.class == class {
			return t.by[k].first
		}
	}
	return ""
}

// total is the requests tallied.
func (t *fuzzFailures) total() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, f := range t.by {
		n += f.count
	}
	return n
}

// keepFuzzFailures stores a row of error for each failed target and class, so
// that query -failed lists them as it lists the failures of the other commands.
func keepFuzzFailures(path string, t *fuzzFailures, argv []string) error {
	keys := t.keys()
	if len(keys) == 0 {
		return nil
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := fuzzRun(st, argv); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, k := range keys {
		target := k.origin + "/"
		if n, err := normalize.URL(target); err == nil {
			target = n
		}
		ent, err := st.UpsertEntity(types.TypeURL, target, now)
		if err != nil {
			return err
		}
		f := t.by[k]
		raw, _ := json.Marshal(map[string]any{"error": f.first, "requests": f.count})
		if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-fuzz", Source: "fuzz", Kind: "error", Payload: raw, Confidence: 0.9, ObservedAt: now}); err != nil {
			return err
		}
	}
	return nil
}
