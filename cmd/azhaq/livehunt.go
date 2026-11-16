package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// liveHunt reads what a run has named on its listeners while it is going,
// from the workspace as a reader sees it (committed rows, through a handle of
// its own: the run's writes are never held back), with the rule hunt applies
// (listenerRecords, listenerPairs, hunt.ListenerRows). With a stream it prints
// each row once, as `found identified` or `found finding`; without one it
// only learns whether a row is stored yet, for the progress line.
type liveHunt struct {
	st    *store.Store // the run's: only to wait for its open batch
	path  string
	runID string
	named func(kind, key, same, more, collector string, fields map[string]any) bool // nil: no stream

	wakeCh chan struct{}
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	stored atomic.Bool // a row is stored: hunt -db lists it

	mu   sync.Mutex // one read at a time
	rd   *store.Store
	args []string
}

// liveHuntMinGap is the least time between two reads; a read that took longer
// waits five times as long, so a big workspace is never read for more than a
// sixth of the time. A run that only waits to learn that a row is stored
// (nothing is printed) reads five times as seldom.
var liveHuntMinGap = time.Second

// The collectors (and the dns kind) listenerRecords reads rows of.
var (
	liveCollectors = []string{"azhaq-ports", "azhaq-http", "azhaq-paths", "azhaq-dirs", "azhaq-advisories", "azhaq-verify"}
	liveKinds      = []string{"dns"}
)

// startLiveHunt starts reading the run st holds (stored at path). named is the
// stream's, nil for a run that only wants to know when a row is stored.
func startLiveHunt(st *store.Store, path string, named func(kind, key, same, more, collector string, fields map[string]any) bool) *liveHunt {
	l := &liveHunt{st: st, path: path, runID: st.RunID(), named: named,
		wakeCh: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go l.loop()
	return l
}

// Stored says a listener row is stored, so `azhaq hunt -db` lists it.
func (l *liveHunt) Stored() bool { return l != nil && l.stored.Load() }

// note wakes the read for a row that can name a listener; it does nothing
// else, as it runs where the row is written.
func (l *liveHunt) note(o types.Observation) {
	if l == nil {
		return
	}
	switch o.Collector {
	case "azhaq-ports", "azhaq-http", "azhaq-paths":
		l.wake()
	}
}

func (l *liveHunt) wake() {
	if l == nil {
		return
	}
	select {
	case l.wakeCh <- struct{}{}:
	default:
	}
}

func (l *liveHunt) loop() {
	defer close(l.done)
	var last time.Time
	var took time.Duration
	for {
		select {
		case <-l.stop:
			return
		case <-l.wakeCh:
		}
		gap := max(liveHuntMinGap, 5*took)
		if l.named == nil {
			gap *= 5
		}
		if wait := time.Until(last.Add(gap)); wait > 0 {
			select {
			case <-l.stop:
				return
			case <-time.After(wait):
			}
		}
		select { // the read below covers what woke it
		case <-l.wakeCh:
		default:
		}
		t := time.Now()
		l.read()
		took, last = time.Since(t), time.Now()
		if l.named == nil && l.stored.Load() {
			return // nothing more to learn
		}
	}
}

// finish stops reading, reads once more (so every row stored by now has
// its line) and lets go of the workspace.
func (l *liveHunt) finish() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		if l.named != nil {
			l.read()
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.rd != nil {
			_ = l.rd.Close()
			l.rd = nil
		}
	})
}

// read prints the rows stored since the last read that have not been printed.
func (l *liveHunt) read() {
	l.mu.Lock()
	defer l.mu.Unlock()
	// What a task observed inside the open batch is not committed until it
	// ends: wait for it, so a row is stored when its line prints.
	l.st.Batch(func() {})
	if l.rd == nil {
		rd, err := store.OpenExisting(l.path)
		if err != nil {
			return
		}
		rd.UseRun(l.runID)
		l.rd, l.args = rd, rd.RunArgs()
	}
	obs, err := l.rd.ObservationsOf(liveCollectors, liveKinds)
	if err != nil {
		return
	}
	for _, p := range namedRows(obs, l.path, runCommand(&graphView{args: l.args})) {
		l.stored.Store(true)
		if l.named == nil {
			return
		}
		line, ok := p.line()
		if ok {
			l.named(line.kind, line.key, line.same, line.more, line.collector, line.fields)
		}
	}
}

// namedRow is a listener row with the record it is read from.
type namedRow struct {
	rec findingRecord
	row hunt.Row
}

// liveRows are the rows hunt lists for the listeners of obs (one for each
// listener and product, and each finding a read proved), unranked.
func namedRows(obs []types.StoredObservation, db, command string) []namedRow {
	set, _, _ := listenerRecords(obs, command)
	less := func(rs []findingRecord) func(i, j int) bool {
		return func(i, j int) bool { return findingLess(rs[i], rs[j]) }
	}
	sort.SliceStable(set.Findings, less(set.Findings))
	sort.SliceStable(set.Identifications, less(set.Identifications))
	pairs := listenerPairs(set)
	ls := make([]hunt.Listener, len(pairs))
	for i, p := range pairs {
		ls[i] = p.l
	}
	rows := hunt.ListenerRows(ls, db)
	out := make([]namedRow, len(rows))
	for i := range rows {
		out[i] = namedRow{pairs[i].rec, rows[i]}
	}
	return out
}

type streamLine struct {
	kind, key, same, more, collector string
	fields                           map[string]any
}

// line is the stream's line for the row. A listener is named again, and its
// line printed again, only when what is stored of it changed: the product, the
// version (a later read can state a more specific one) or the label; a finding
// is one line for each kind of read and advisory. The fields are the row's of
// `hunt -json`, but its rank (known only once every row is ordered), and its
// type and kind, which the line's own say.
func (r namedRow) line() (streamLine, bool) {
	id := r.row.Ident
	if id == nil {
		return streamLine{}, false
	}
	raw, err := json.Marshal(r.row)
	if err != nil {
		return streamLine{}, false
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return streamLine{}, false
	}
	for _, k := range []string{"rank", "type", "kind"} {
		delete(fields, k)
	}
	port := ""
	if id.Port > 0 {
		port = ":" + strconv.Itoa(id.Port)
	}
	l := streamLine{key: id.Host + port, collector: r.rec.Collector, fields: fields}
	if l.collector == "" {
		l.collector = "azhaq"
	}
	label := " (" + id.Label + ")"
	named := strings.TrimSpace(id.Product + " " + id.Version)
	listener := l.key + "|" + advisory.ProductKey(id.Product) + "|" + id.Version + "|" + id.Label
	if r.row.Tier == proof.TierFinding {
		l.kind = "finding"
		l.same = listener + "|" + id.What + "|" + id.AdvisoryID
		parts := []string{named, id.What, id.AdvisoryID}
		l.more = strings.Join(slicesNonEmpty(parts), " ") + label
		return l, true
	}
	l.kind, l.same = "identified", listener
	if id.Version == "" {
		named += ", no version seen"
	}
	l.more = named + label
	return l, true
}

func slicesNonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// huntSoFar is the line of a progress report once a listener row is stored.
func huntSoFar(path string) string { return fmt.Sprintf("azhaq hunt -db %s", path) }

type liveKey struct{}

// withLiveHunt carries l to the stages that store rows after the tasks end.
func withLiveHunt(ctx context.Context, l *liveHunt) context.Context {
	return context.WithValue(ctx, liveKey{}, l)
}

// liveWake tells the live read a stage stored a row.
func liveWake(ctx context.Context) {
	if l, _ := ctx.Value(liveKey{}).(*liveHunt); l != nil {
		l.wake()
	}
}
