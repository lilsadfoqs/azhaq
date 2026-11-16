package store

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// Diff is what differs between two runs of a target.
type Diff struct {
	Added   []types.Entity
	Removed []types.Entity
	NewObs  []types.StoredObservation
	// Paired counts the URLs the older run lacks and the newer has that stand
	// for one the newer lacks and the older has: same place, same query
	// names, and values that are numbers. They are in neither Added nor Removed.
	Paired int
}

// Compare lists what the newer run has that the older lacks, and the
// reverse. A URL is the same URL by normalize.Identity (query names in any
// order, token values and a session path parameter ignored); one entity
// stands for each identity.
func Compare(old, neu *Store) (Diff, error) {
	var d Diff
	oe, err := old.Entities()
	if err != nil {
		return d, err
	}
	ne, err := neu.Entities()
	if err != nil {
		return d, err
	}
	om, nm := byIdentity(oe), byIdentity(ne)
	var added, removed []types.Entity
	for _, k := range sortedKeys(nm) {
		if _, ok := om[k]; !ok {
			added = append(added, nm[k])
		}
	}
	for _, k := range sortedKeys(om) {
		if _, ok := nm[k]; !ok {
			removed = append(removed, om[k])
		}
	}
	added, removed, perVisit, paired := pairNumbers(added, removed)
	d.Added, d.Removed, d.Paired = added, removed, paired

	oo, err := old.Observations()
	if err != nil {
		return d, err
	}
	no, err := neu.Observations()
	if err != nil {
		return d, err
	}
	oc, nc := newCtx(oo, perVisit), newCtx(no, perVisit)
	seen := map[string]bool{}
	for _, o := range oo {
		if comparable(o) {
			seen[oc.key(o)] = true
		}
	}
	for _, o := range no {
		if comparable(o) && !seen[nc.key(o)] {
			d.NewObs = append(d.NewObs, o)
		}
	}
	return d, nil
}

// entityKey identifies an entity across runs.
func entityKey(e types.Entity) string {
	if e.Type == types.TypeURL {
		return string(e.Type) + "\x00" + normalize.Identity(e.Key, nil)
	}
	return string(e.Type) + "\x00" + e.Key
}

// byIdentity maps each identity to its entity; of several spellings the first
// by key stands for it, the same one in every run.
func byIdentity(es []types.Entity) map[string]types.Entity {
	es = append([]types.Entity(nil), es...)
	sort.SliceStable(es, func(i, j int) bool { return es[i].Key < es[j].Key })
	out := make(map[string]types.Entity, len(es))
	for _, e := range es {
		if k := entityKey(e); out[k].Key == "" {
			out[k] = e
		}
	}
	return out
}

func sortedKeys(m map[string]types.Entity) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// pairNumbers cancels a URL that is new against one that is gone when they
// are one page whose query value changed between the runs: the same place and
// query names, and every value that differs a number on both sides (a
// conversation id, a counter). It returns what is left, and the names whose
// values were measured to change this way.
func pairNumbers(added, removed []types.Entity) (a, r []types.Entity, perVisit map[string]bool, paired int) {
	shape := func(raw string) string {
		base, params := normalize.Parts(raw)
		for _, p := range params {
			base += "&" + p.Name
		}
		return base
	}
	byShape := map[string][]int{}
	for i, e := range removed {
		if e.Type == types.TypeURL {
			s := shape(e.Key)
			byShape[s] = append(byShape[s], i)
		}
	}
	gone := map[int]bool{} // removed entries paired
	paid := map[int]bool{} // added entries paired
	perVisit = map[string]bool{}
	for ai, e := range added {
		if e.Type != types.TypeURL {
			continue
		}
		for _, ri := range byShape[shape(e.Key)] {
			if gone[ri] {
				continue
			}
			if names, ok := numbersDiffer(e.Key, removed[ri].Key); ok {
				gone[ri], paid[ai] = true, true
				for _, n := range names {
					perVisit[n] = true
				}
				paired++
				break
			}
		}
	}
	for i, e := range added {
		if !paid[i] {
			a = append(a, e)
		}
	}
	for i, e := range removed {
		if !gone[i] {
			r = append(r, e)
		}
	}
	return a, r, perVisit, paired
}

// numbersDiffer says two URLs of one shape differ, and only by values that
// are numbers; it names the parameters that differ.
func numbersDiffer(a, b string) (names []string, ok bool) {
	_, pa := normalize.Parts(a)
	_, pb := normalize.Parts(b)
	if len(pa) != len(pb) {
		return nil, false
	}
	for i := range pa {
		if pa[i].Name != pb[i].Name || pa[i].HasValue != pb[i].HasValue {
			return nil, false
		}
		if pa[i].Value == pb[i].Value {
			continue
		}
		if !normalize.Number(pa[i].Value) || !normalize.Number(pb[i].Value) {
			return nil, false
		}
		names = append(names, pa[i].Name)
	}
	return names, len(names) > 0
}

// cmpCtx is what comparing a run's rows measured in the run: the query names
// whose numbers changed between the two runs, and the form field names that
// are tokens (an anti-forgery token this run's pages carry).
type cmpCtx struct {
	perVisit   map[string]bool
	tokenNames map[string]bool
}

func newCtx(obs []types.StoredObservation, perVisit map[string]bool) cmpCtx {
	c := cmpCtx{perVisit: perVisit, tokenNames: map[string]bool{}}
	for _, o := range obs {
		if o.Collector != "azhaq-crawl" || o.Kind != "form" {
			continue
		}
		var f struct {
			Fields []string `json:"fields"`
		}
		_ = json.Unmarshal(o.Payload, &f)
		for _, n := range f.Fields {
			if normalize.TokenShaped(n) {
				c.tokenNames[n] = true
			}
		}
	}
	return c
}

func (c cmpCtx) key(o types.StoredObservation) string {
	return o.Collector + "\x00" + o.Kind + "\x00" + c.stablePayload(o)
}

// comparable says a row is one diff compares. A checkpoint of a port scan is
// the scan's progress at the moment it was kept (the ports done so far, which
// depend on timing), and the scan's own row follows it.
func comparable(o types.StoredObservation) bool {
	if o.Collector != "azhaq-ports" || o.Kind != "ports" {
		return true
	}
	var r struct {
		Checkpoint bool `json:"checkpoint"`
	}
	_ = json.Unmarshal(o.Payload, &r)
	return !r.Checkpoint
}

// volatileAnswer are the fields of an answer's evidence that every collector's
// rows share (fetch.Evidence and the http row): they hold the bytes of one
// request, when and how long it took, not what the page is.
var volatileAnswer = []string{"body_hash", "auth", "length", "words", "lines", "ms", "ip", "json_ids", "head", "trace_excerpt", "trace_offset", "answer_hash", "response_headers", "body_excerpt", "body_length", "body_cut", "body_url", "asked_at"}

// volatileTimes are the fields that name the moment a row was asked, in any
// row; dotted names are fields of an object.
var volatileTimes = []string{"observed_at", "proof.observed_at"}

// volatileByRow lists, for a row type ("collector kind"), the fields diff
// leaves out beyond those above, because they record how the row was asked,
// not what the target answered. Each is a field of the row's type
// (httprow.Row, portscan.Row, the proof of a verify row): TestVolatileFields
// holds the names to those.
//
//   - azhaq-http application: cookies are the ones the answer set, and the
//     server hands a session cookie to the first request that has none.
//   - azhaq-advisories advisory: origin is the name of the address the
//     confirming read was sent to. An address with several names is scanned
//     under each in no fixed order, and the first one scanned supplies it.
//     names, host and port stay.
//   - azhaq-paths sweep: what became of each check of the sweep (sent,
//     answered from an earlier request, described). The crawl runs at the
//     same time, so a check it already asked is answered from its cache in one
//     run and sent in the other. planned and listed stay.
var volatileByRow = map[string][]string{
	"azhaq-advisories advisory": {"origin"},
	"azhaq-http application":    {"cookies"},
	"azhaq-paths sweep":         {"sent", "answered", "described", "product_checks.sent"},
}

// timeoutNote is what Go adds to a timeout's text for where it ran out: it is
// the same timeout whether it came while the headers or the body were read.
var timeoutNote = lazyre.New(` \(Client\.Timeout[^)]*\)`)

// stablePayload is the payload as diff compares it: the volatile fields
// dropped, per-source timings dropped, response headers reduced to their
// names (rate-limit counters and request IDs change on every request), a
// catch-all control reduced to its answer, and the identifiers of one visit
// folded: a URL by its identity, a form field name that is a token, a secret
// that is such a token, the message id of a DNS read.
func (c cmpCtx) stablePayload(o types.StoredObservation) string {
	var m map[string]any
	if json.Unmarshal(o.Payload, &m) != nil {
		return string(o.Payload)
	}
	row := o.Collector + " " + o.Kind
	for _, k := range volatileAnswer {
		delete(m, k)
	}
	for _, k := range volatileTimes {
		dropPath(m, k)
	}
	for _, k := range volatileByRow[row] {
		dropPath(m, k)
	}
	if srcs, ok := m["sources"].(map[string]any); ok {
		for _, v := range srcs {
			if row, ok := v.(map[string]any); ok {
				delete(row, "seconds")
				delete(row, "waited_seconds")
			}
		}
	}
	if ctl, ok := m["control"].(map[string]any); ok {
		// The control's path is random in every run, its size follows the
		// name when the page echoes it, and its directory is whichever
		// baseline was ready when the row was judged (the site root's, or
		// the row's own directory): none of them is a fact about the app.
		// What it proved is its status, type and title.
		delete(ctl, "url")
		delete(ctl, "size")
	}
	if h, ok := m["headers"].(map[string]any); ok {
		names := make([]string, 0, len(h))
		for k := range h {
			names = append(names, k)
		}
		sort.Strings(names)
		m["headers"] = names
	}
	switch row {
	case "azhaq-http error":
		if s, ok := m["error"].(string); ok {
			m["error"] = timeoutNote.ReplaceAllString(s, "")
		}
	case "azhaq-crawl form":
		if fs, ok := m["fields"].([]any); ok {
			for i, f := range fs {
				if s, ok := f.(string); ok && normalize.TokenShaped(s) {
					fs[i] = "{}"
				}
			}
		}
	case "azhaq-js secrets":
		// A value the run's forms name as a field is that form's anti-forgery
		// token: one per page load, not a key kept in a script.
		if ss, ok := m["secrets"].([]any); ok {
			for _, s := range ss {
				if sm, ok := s.(map[string]any); ok {
					if v, _ := sm["value"].(string); c.tokenNames[v] {
						delete(sm, "value")
						delete(sm, "context")
						delete(sm, "entropy")
					}
				}
			}
		}
	case "azhaq-verify verify", "azhaq-verify verify-declined":
		// A DNS message starts with a random id, and a row cuts its bytes by
		// how many characters they take to write (an id of two high bytes
		// takes more), so the bytes differ in every request. The facts read
		// from them (label, product, version, the rcode in evidence) stay.
		if m["service"] == "dns" {
			for _, k := range []string{"proof.request_bytes", "proof.excerpt", "proof.reproduce"} {
				dropPath(m, k)
			}
			if e, _ := m["evidence"].(string); strings.HasPrefix(e, `\x`) {
				delete(m, "evidence")
			}
		}
	}
	out, err := json.Marshal(c.foldURLs(m))
	if err != nil {
		return string(o.Payload)
	}
	return string(out)
}

// foldURLs writes every URL in a row (a link, a redirect's Location, a form's
// action, a hop) as its identity.
func (c cmpCtx) foldURLs(v any) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") {
			return normalize.Identity(x, c.perVisit)
		}
	case map[string]any:
		for k, e := range x {
			x[k] = c.foldURLs(e)
		}
	case []any:
		for i, e := range x {
			x[i] = c.foldURLs(e)
		}
	}
	return v
}

// dropPath deletes a field of a row; a dotted name is a field of an object.
func dropPath(m map[string]any, path string) {
	k, rest, nested := strings.Cut(path, ".")
	if !nested {
		delete(m, k)
		return
	}
	if sub, ok := m[k].(map[string]any); ok {
		dropPath(sub, rest)
	}
}
