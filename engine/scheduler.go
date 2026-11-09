package engine

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// batchesInFlight is how many batches one collector may run at once.
const batchesInFlight = 4

// perTemplate is how many URLs of one template (/product?id={n}) are
// fetched by default: all. -per-template N bounds it; the rest stay in the
// graph as found, not visited.
const perTemplate = 1 << 30

// RunLocal is the built-in scheduler. Work flows: a seed's items start as
// soon as a worker is free, and the hints they return are queued at once,
// so a slow item (a CT log taking 25 s) never holds back the rest.
//
// Items on the seed's own host run before fan-out items, but a reserve of
// the item budget is kept for fan-out so a chatty application cannot starve
// domain-level collectors. Batch collectors (DNS) take many seeds per call
// and have their own budget, MaxNames.
func (e *Engine) RunLocal(ctx context.Context, seeds []types.Seed, b Budgets) error {
	if b.MaxDepth <= 0 {
		b.MaxDepth = 1
	}
	if b.Parallel <= 0 {
		b.Parallel = DefaultBudgets().Parallel
	}
	if b.MaxNames <= 0 {
		b.MaxNames = DefaultBudgets().MaxNames
	}
	s := &scheduler{
		e:         e,
		b:         b,
		origin:    seedOrigin(seeds),
		seen:      map[string]bool{},
		tmpl:      map[string]int{},
		named:     map[string]bool{},
		catchHeld: map[string]bool{},
		flight:    newNamedFlight(),
		batch:     map[string][]task{},
		batchBusy: map[string]int{},
		parked:    map[string][]task{},
		results:   make(chan finished, b.Parallel),
		ctx:       ctx,
		secure:    givenHTTPS(seeds),
		schemes:   map[string]bool{},
		asked:     map[string]bool{},
		waiting:   map[string][]heldHint{},
	}
	if !b.Passive {
		s.reserve = fanReserve(b)
	}
	if e.Store != nil {
		catalog.Claim = e.Store.Claim
		defer func() { catalog.Claim = nil }()
		egress.SetOnDenied(e.noteDenied)
		egress.SetOnPortSkip(e.notePortSkip)
		defer func() { egress.SetOnDenied(nil); egress.SetOnPortSkip(nil) }()
	}
	if b.Resume && e.Store != nil {
		if err := s.restore(); err != nil {
			return err
		}
	} else {
		expanded := expandDerived(seeds, map[string]bool{})
		e.persistSeeds(expanded)
		for _, seed := range expanded {
			s.add(seed, 0, false)
		}
	}
	s.flush()
	s.loop(ctx)
	s.flush()
	leftover := s.leftover()
	e.setCaps(s.caps())
	if len(leftover) > 0 && s.ran+s.names > 0 {
		e.markCapped()
	}
	if e.Store != nil {
		_ = e.Store.SaveLeftover(leftover)
	}
	return ctx.Err()
}

type task struct {
	col   string
	seed  types.Seed
	depth int
	prio  int // 0: the seed's own host or IP; 1: fan-out
	tier  int // within a prio, what it is worth under a budget (tierOf)
}

type finished struct {
	batch   string
	tasks   []task
	metas   []types.RunMeta
	errs    []error
	partial bool // early hints from a task still running

	scheme string // the host whose http://host/ was asked (scheme.go)
	same   bool   // and whether it is the https site
}

type scheduler struct {
	e      *Engine
	b      Budgets
	origin originSet

	seen      map[string]bool // seeds queued at some depth
	tmpl      map[string]int  // URLs queued per template
	named     map[string]bool // URL seeds a script named, by seed key (the hints of azhaq-js)
	catchHeld map[string]bool // of those, the ones not asked: their origin answers every path with one page
	flight    namedFlight
	queue     [2][]task

	batch     map[string][]task // seeds waiting for a batch collector
	batchBusy map[string]int    // batches in flight per collector
	parked    map[string][]task // seedKey + "\x00" + collector it waits for

	ran, originRan, reserve int
	names                   int // seeds handed to batch collectors
	inflight                int
	beyond                  []types.Seed    // distinct seeds past MaxDepth that a collector of the run would run on
	beyondSeen              map[string]bool // keys of the seeds found past MaxDepth, however often
	atLimit                 map[string]bool // names past MaxDepth that DNS-only collectors ran on
	results                 chan finished

	// The frontier as the store records it (see store.Task): tasks
	// planned and tasks done since the last flush.
	planned []store.Task
	done    []string
	stopped []store.Stopped
	held    []task // work that contacts targets, kept back once the budget is spent
	retry   []task // work the budget stopped before, cheapest first: one at a time

	// Tasks of collectors that ask with the session but not through the URLs
	// asked again (Info.Redo), by work id, until a later good check proves
	// their requests were made with a live session.
	stretch map[string]*stretchEnt
	again   map[string]bool // of those, the running ones to run again when they end
	reruns  map[string]int  // how often each was run again

	// Tasks lent to remote workers (Engine.Workers).
	leases  map[string]lease
	remote  int // of inflight, the leased ones
	leaseNo int

	// http://host/ hints on a host given as https://host/ (scheme.go).
	ctx     context.Context
	secure  httpsGiven            // where the run was given https
	schemes map[string]bool       // host → its http URLs are the https site's
	asked   map[string]bool       // hosts whose http://host/ was asked
	waiting map[string][]heldHint // hints held for that answer

	rw reserveWatch // the tasks the web reserve of a service waits for
}

// stretchEnt is a task of the stretch the session check has not vouched for:
// the count fetch.GoodChecks had when it began and when it ended (-1: it runs).
type stretchEnt struct {
	t          task
	begin, end int64
}

type lease struct {
	t     task
	until time.Time
	gen   int // the session the task was lent under
}

// record notes a planned task for the store.
func (s *scheduler) record(t task) {
	s.noteRecorded(t)
	if s.e.Store != nil {
		s.planned = append(s.planned, store.Task{ID: workID(t.col, t.seed), Collector: t.col, Seed: t.seed, Depth: t.depth, Prio: t.prio})
	}
}

// finish notes a task that will not run again in this run.
func (s *scheduler) finish(t task) {
	s.noteFinished(t)
	if s.e.Store != nil {
		s.done = append(s.done, workID(t.col, t.seed))
	}
}

// flush writes the noted tasks in one transaction.
func (s *scheduler) flush() {
	if s.e.Store == nil || len(s.planned)+len(s.done)+len(s.stopped) == 0 {
		return
	}
	if err := s.e.Store.SaveTasks(s.planned, s.done, s.stopped); err != nil {
		fmt.Fprintf(os.Stderr, "azhaq: recording tasks: %v\n", err)
	}
	s.planned, s.done, s.stopped = s.planned[:0], s.done[:0], s.stopped[:0]
}

// itemsSpent says -max-items tasks have been started in this run.
func (s *scheduler) itemsSpent() bool { return s.b.MaxItems > 0 && s.ran >= s.b.MaxItems }

// originSpent says the tasks on the seed's own hosts have used what -max-items
// leaves them besides the reserve for fan-out.
func (s *scheduler) originSpent() bool {
	return s.b.MaxItems > 0 && s.originRan >= s.b.MaxItems-s.reserve
}

// restore rebuilds the queues from the run's recorded tasks: the rest are
// queued again (behind the task they wait for, when that is not done
// either). Done ones do not count against -max-items and -max-names: a cap
// holds for each run, as -max-requests does, so a resume that is given the
// same cap goes on instead of finding it spent.
func (s *scheduler) restore() error {
	rows, err := s.e.Store.Tasks()
	if err != nil {
		return err
	}
	open := map[string]map[string]bool{} // seed → collectors not done
	for _, r := range rows {
		seed := normalize.Seed(r.Seed)
		k := seedKey(seed)
		if !s.seen[k] {
			s.seen[k] = true
			if seed.Type == types.TypeURL && webextract.Templated(seed.Key()) {
				s.tmpl[webextract.Template(seed.Key())]++
			}
		}
		if open[k] == nil {
			open[k] = map[string]bool{}
		}
		if !r.Done {
			open[k][r.Collector] = true
		}
	}
	// What the resume is told to leave out (-skip, -passive, an active
	// technique without its flag) is left out of the tasks the stopped run
	// kept as well: they end here, and the summary counts them.
	var again, left []string
	omitted := map[string]int{}
	for _, r := range rows {
		col, ok := s.e.Cat.Get(r.Collector)
		if r.Done || !ok || s.allowed(col, normalize.Seed(r.Seed)) {
			continue
		}
		delete(open[seedKey(normalize.Seed(r.Seed))], r.Collector)
		omitted[r.Collector]++
		left = append(left, r.ID)
	}
	for _, r := range rows {
		col, ok := s.e.Cat.Get(r.Collector)
		if r.Done || !ok {
			continue
		}
		seed := normalize.Seed(r.Seed)
		k := seedKey(seed)
		if !s.allowed(col, seed) {
			continue
		}
		t := task{col: r.Collector, seed: seed, depth: r.Depth, prio: r.Prio}
		again = append(again, r.ID)
		if after := catalog.InfoOf(col).After; after != "" && open[k][after] {
			pk := k + "\x00" + after
			s.parked[pk] = append(s.parked[pk], t)
			continue
		}
		if _, batch := col.(catalog.Batcher); r.Tries > 0 && !batch {
			// Run alone, it gets the whole budget: a sweep started next to
			// it cannot take the requests a cheap task needs.
			s.retry = append(s.retry, t)
			continue
		}
		s.enqueue(t)
	}
	for _, name := range slices.Sorted(maps.Keys(omitted)) {
		fetch.Note(fmt.Sprintf("%s: %d tasks the run left are not run, as this resume leaves the collector out (-skip, -passive, or an active technique without its flag)", name, omitted[name]))
	}
	if len(left) > 0 {
		s.done = append(s.done, left...)
	}
	// What a lower -depth left unasked is asked now, as far as this run's
	// -depth goes.
	if left, err := s.e.Store.LoadLeftover(); err == nil && len(left) > 0 {
		st, _ := s.e.Store.Stats()
		for _, seed := range left {
			if !s.seen[seedKey(normalize.Seed(seed))] {
				s.add(seed, max(st.Depth, 1), true)
			}
		}
	}
	s.restoreCatchAll(rows)
	// A task that ran but whose end was not recorded runs again whole.
	return s.e.Store.Forget(again)
}

// restoreCatchAll gives the catch-all rule what the stopped run had learned:
// which URLs scripts named, how they answered, and which directories it
// stopped asking in. Else a resume would ask again, from the start, what the
// run had already settled.
func (s *scheduler) restoreCatchAll(rows []store.Task) {
	if s.b.CatchAllStop <= 0 {
		return
	}
	var named []string
	for _, r := range rows {
		if seed := normalize.Seed(r.Seed); seed.Type == types.TypeURL && seed.Keys[types.ViaKey] == types.ViaScript && !s.named[seedKey(seed)] {
			s.named[seedKey(seed)] = true
			named = append(named, seed.Key())
		}
	}
	fetch.RestoreNamed(named)
}

// add queues every allowed collector for a seed. Hints are checked against
// the scope; the run's own seeds are not.
func (s *scheduler) add(raw types.Seed, depth int, hint bool) {
	seed := normalize.Seed(raw)
	if seed.Key() == "" {
		return
	}
	if hint && !s.b.Scope.AllowsSeed(seed) {
		if seed.Type == types.TypeURL {
			egress.NotePortSkip(seed.Key())
		}
		return
	}
	if hint {
		var held bool
		if seed, held = s.scheme(seed, depth); held {
			return
		}
	}
	k := seedKey(seed)
	if s.seen[k] {
		return
	}
	if seed.Type == types.TypeURL {
		// The user's own rule (-deny-path): the URL stays in the map, listed
		// as not requested.
		if rule := s.b.Scope.DeniedPath(seed.Key()); rule != "" {
			s.seen[k] = true
			s.e.noteDenied(seed.Key(), rule)
			return
		}
	}
	if depth >= s.b.MaxDepth {
		s.pastDepth(seed, k)
		s.atDepthLimit(seed, depth, k)
		return
	}
	s.seen[k] = true
	if hint && seed.Type == types.TypeURL && webextract.Templated(seed.Key()) {
		t := webextract.Template(seed.Key())
		if s.tmpl[t] >= s.perTemplate() {
			return
		}
		s.tmpl[t]++
	}
	prio := 1
	if s.origin.owns(seed) {
		prio = 0
	}
	cols := s.e.Cat.Where(seed.Type)
	planned := map[string]bool{}
	for _, col := range cols {
		if s.allowed(col, seed) {
			planned[col.Name()] = true
		}
	}
	for _, col := range cols {
		if !planned[col.Name()] {
			continue
		}
		t := task{col: col.Name(), seed: seed, depth: depth, prio: prio}
		s.record(t)
		if after := catalog.InfoOf(col).After; after != "" && planned[after] {
			pk := k + "\x00" + after
			s.parked[pk] = append(s.parked[pk], t)
			continue
		}
		s.enqueue(t)
	}
}

// pastDepth keeps a seed found past -depth for a larger one to ask, once
// however often it is found, and only when a collector the run has would
// run on it: a found path no sweep takes as a start, a name the run does
// not look up, has nothing for a larger -depth to ask.
func (s *scheduler) pastDepth(seed types.Seed, k string) {
	if s.beyondSeen[k] {
		return
	}
	if s.beyondSeen == nil {
		s.beyondSeen = map[string]bool{}
	}
	s.beyondSeen[k] = true
	for _, col := range s.e.Cat.Where(seed.Type) {
		if s.allowed(col, seed) && !s.skip(task{col: col.Name(), seed: seed}) {
			s.beyond = append(s.beyond, seed)
			return
		}
	}
}

// atDepthLimit runs the collectors that ask DNS only on a name an active
// technique found and resolved, so -permute varies what -dns-brute found
// whatever -depth says. Other work on the name stays past the limit.
func (s *scheduler) atDepthLimit(seed types.Seed, depth int, k string) {
	if seed.Type != types.TypeHostname || seed.Keys[types.LiveKey] == "" || s.atLimit[k] {
		return
	}
	for _, col := range s.e.Cat.Where(seed.Type) {
		if !catalog.InfoOf(col).AtLimit || !s.allowed(col, seed) {
			continue
		}
		if s.atLimit == nil {
			s.atLimit = map[string]bool{}
		}
		s.atLimit[k] = true
		t := task{col: col.Name(), seed: seed, depth: depth, prio: 1}
		s.record(t)
		s.enqueue(t)
	}
}

func (s *scheduler) perTemplate() int {
	if s.b.PerTemplate > 0 {
		return s.b.PerTemplate
	}
	return perTemplate
}

// drop discards the tasks that waited for col on a seed, and the tasks
// that waited for those, down the chain.
func (s *scheduler) drop(seedK, col string) {
	pk := seedK + "\x00" + col
	waiting := s.parked[pk]
	delete(s.parked, pk)
	for _, w := range waiting {
		s.finish(w)
		s.drop(seedK, w.col)
	}
}

// unpark queues the tasks that waited for t.
func (s *scheduler) unpark(t task) {
	pk := seedKey(t.seed) + "\x00" + t.col
	for _, w := range s.parked[pk] {
		s.enqueue(w)
	}
	delete(s.parked, pk)
}

func (s *scheduler) enqueue(t task) {
	col, _ := s.e.Cat.Get(t.col)
	if _, ok := col.(catalog.Batcher); ok {
		s.batch[t.col] = append(s.batch[t.col], t)
		return
	}
	// Worth first, arrival order within a tier: a front page found late
	// goes ahead of the archived URLs an archive listed before it, so a
	// budget is spent on what the application serves before on what it
	// once served.
	t.tier = tierOf(t.seed)
	q := s.queue[t.prio]
	i := len(q)
	for i > 0 && q[i-1].tier > t.tier {
		i--
	}
	q = append(q, task{})
	copy(q[i+1:], q[i:])
	q[i] = t
	s.queue[t.prio] = q
}

// tierOf orders a host's work by what it is worth under a budget: a
// service and its front page first, then its API and description paths,
// then the pages links and scripts name, and what only an archive lists
// last. An archive's static assets are never hints (urlcol lists them).
func tierOf(seed types.Seed) int {
	if seed.Type != types.TypeURL {
		return 0
	}
	if seed.Keys[types.ViaKey] == types.ViaArchive {
		return 3
	}
	u, err := url.Parse(seed.Key())
	if err != nil {
		return 2
	}
	switch {
	case u.Path == "" || u.Path == "/":
		return 0
	case seed.Keys[types.KnownLocationKey] != "" && guessedGraphQL(u.Path):
		// A GraphQL location a path sweep found is a guess about the origin:
		// the endpoints scripts and descriptions name go first, so a budget
		// reads their schemas before it is spent on a guess.
		return 2
	case webextract.ClassifyURL(seed.Key()) == "api":
		return 1
	default:
		return 2
	}
}

func guessedGraphQL(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "/graphql") || strings.Contains(path, "/graphiql")
}

// allowed applies the run's policy: -passive keeps only collectors that do
// not contact the target, and an active technique needs its flag, an
// -allow scope, and a seed inside it.
func (s *scheduler) allowed(col catalog.Collector, seed types.Seed) bool {
	return s.b.Allows(col, seed)
}

// Allows applies the run's policy to one collector on one seed.
func (b Budgets) Allows(col catalog.Collector, seed types.Seed) bool {
	if b.Skip[col.Name()] {
		return false
	}
	in := catalog.InfoOf(col)
	switch in.Kind {
	case catalog.Passive:
		return true
	case catalog.Active:
		return in.Flag != "" && b.Active[in.Flag] && len(b.Scope.Allow) > 0 && b.Scope.AllowsSeed(seed)
	default:
		return !b.Passive
	}
}

// contacts says whether a task's collector sends requests to targets.
func (s *scheduler) contacts(t task) bool {
	col, ok := s.e.Cat.Get(t.col)
	return ok && catalog.InfoOf(col).Kind != catalog.Passive
}

func (s *scheduler) skip(t task) bool {
	col, ok := s.e.Cat.Get(t.col)
	if !ok {
		return true
	}
	sk, ok := col.(catalog.Skipper)
	return ok && sk.Skip(t.seed)
}

func (s *scheduler) loop(ctx context.Context) {
	w := s.e.Workers
	var claims chan claim
	var dones chan remoteDone
	var tick <-chan time.Time
	if w != nil {
		defer w.finish()
		claims, dones = w.claims, w.done
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		tick = t.C
		s.leases = map[string]lease{}
	}
	for {
		s.releaseMapped()
		if ctx.Err() == nil {
			s.redoSession()
			s.dispatch(ctx)
		} else {
			s.release()
		}
		s.flush()
		if s.inflight == 0 {
			if ctx.Err() == nil {
				// The requests since the last check are checked too.
				fetch.EndCheck(ctx)
				s.redoSession()
				s.dispatch(ctx)
				s.flush()
			}
			if s.inflight == 0 {
				return
			}
		}
		select {
		case f := <-s.results:
			s.handle(f)
		case c := <-claims:
			s.lend(ctx, c)
		case d := <-dones:
			s.giveBack(ctx, d)
		case <-tick:
			s.expire()
		}
	}
}

// redoSession asks again the pages whose answers a session that ended gave
// without it (fetch.TakeRedo): what the collectors reported of them is
// dropped, and their tasks run again.
func (s *scheduler) redoSession() {
	s.redoStretch()
	urls := fetch.TakeRedo()
	if len(urls) == 0 || s.e.Store == nil {
		return
	}
	var touch []catalog.Collector
	for _, col := range s.e.Cat.Where(types.TypeURL) {
		if in := catalog.InfoOf(col); in.Kind == catalog.Touch && !in.Redo {
			touch = append(touch, col)
		}
	}
	names := make([]string, len(touch))
	for i, col := range touch {
		names[i] = col.Name()
	}
	for _, raw := range urls {
		seed := normalize.Seed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}})
		if seed.Key() == "" || !s.seen[seedKey(seed)] {
			continue
		}
		var keys []string
		for _, col := range touch {
			keys = append(keys, workID(col.Name(), seed))
		}
		for _, col := range touch {
			if f, ok := col.(catalog.Forgetter); ok {
				f.Forget(seed.Key())
			}
		}
		_ = s.e.Store.Unsee(keys)
		if ent, err := s.e.Store.UpsertEntity(seed.Type, seed.Key(), time.Now().UTC()); err == nil {
			_ = s.e.Store.DropObservations(ent.ID, names)
		}
		delete(s.seen, seedKey(seed))
		s.add(seed, 0, true)
	}
}

// noteStretch keeps a task that asks with the session by means the URL list
// cannot ask again.
func (s *scheduler) noteStretch(t task) {
	col, ok := s.e.Cat.Get(t.col)
	if !ok || !catalog.InfoOf(col).Redo {
		return
	}
	if s.stretch == nil {
		s.stretch = map[string]*stretchEnt{}
	}
	s.stretch[workID(t.col, t.seed)] = &stretchEnt{t: t, begin: fetch.GoodChecks(), end: -1}
}

// endStretch notes when a task ended; one that did not finish is run by
// azhaq resume, and one that was running when its session ended runs again.
func (s *scheduler) endStretch(t task, meta types.RunMeta) {
	id := workID(t.col, t.seed)
	ent := s.stretch[id]
	if ent == nil {
		return
	}
	if meta.Status == types.StatusCapped || meta.Status == types.StatusCancelled {
		delete(s.stretch, id)
		delete(s.again, id)
		return
	}
	ent.end = fetch.GoodChecks()
	if s.again[id] {
		delete(s.again, id)
		s.rerun(t)
	}
}

// redoStretch runs again the tasks that asked with a session that ended,
// and forgets those a later good check vouched for.
func (s *scheduler) redoStretch() {
	if len(s.stretch) == 0 || s.e.Store == nil {
		return
	}
	if from, ok := fetch.TakeStretch(); ok {
		for id, ent := range s.stretch {
			switch {
			case ent.begin > from:
				// began with the new session
			case ent.end < 0:
				if s.again == nil {
					s.again = map[string]bool{}
				}
				s.again[id] = true
			default:
				s.rerun(ent.t)
			}
		}
	}
	// A check that held vouches for what ended before it.
	now := fetch.GoodChecks()
	for id, ent := range s.stretch {
		if ent.end >= 0 && ent.end < now {
			delete(s.stretch, id)
		}
	}
}

// rerun asks a task's work again: what it reported is dropped and the
// collector forgets it did the work.
func (s *scheduler) rerun(t task) {
	col, ok := s.e.Cat.Get(t.col)
	if !ok || s.e.Store == nil {
		return
	}
	id := workID(t.col, t.seed)
	if s.reruns[id] >= 1 {
		// It ended the new session as well, or the sign-in did not hold.
		fetch.Note(fmt.Sprintf("%s on %s ran with a session that ended again after it was run again; it is not run a third time: azhaq resume runs it", t.col, t.seed.Key()))
		delete(s.stretch, id)
		return
	}
	if s.reruns == nil {
		s.reruns = map[string]int{}
	}
	s.reruns[id]++
	if f, ok := col.(catalog.Forgetter); ok {
		f.Forget(t.seed.Key())
	}
	_ = s.e.Store.Unsee([]string{workID(t.col, t.seed)})
	if ent, err := s.e.Store.UpsertEntity(t.seed.Type, t.seed.Key(), time.Now().UTC()); err == nil {
		_ = s.e.Store.DropObservations(ent.ID, []string{t.col})
	}
	delete(s.stretch, workID(t.col, t.seed))
	s.record(t)
	s.enqueue(t)
}

// lend hands a worker the next task it may run: one that contacts
// targets, is not Local, and is not a batch.
func (s *scheduler) lend(ctx context.Context, c claim) {
	// A signed-in run that lost its session lends nothing: its requests
	// would be answered without it.
	if ctx.Err() != nil || fetch.SessionLost() != nil {
		c.reply <- nil
		return
	}
	for p := 0; p < 2; p++ {
		for i := 0; i < len(s.queue[p]); i++ {
			t := s.queue[p][i]
			col, ok := s.e.Cat.Get(t.col)
			if !ok || !s.contacts(t) || catalog.InfoOf(col).Local {
				continue
			}
			if s.itemsSpent() || egress.Spent() || (p == 0 && s.originSpent()) {
				break
			}
			s.queue[p] = append(s.queue[p][:i:i], s.queue[p][i+1:]...)
			if s.skip(t) {
				s.finish(t)
				s.unpark(t)
				i--
				continue
			}
			s.ran++
			if p == 0 {
				s.originRan++
			}
			s.inflight++
			s.noteStretch(t)
			s.remote++
			s.leaseNo++
			id := fmt.Sprintf("%s-%d", workID(t.col, t.seed), s.leaseNo)
			hold := s.e.Workers.Lease
			if hold <= 0 {
				hold = 15 * time.Minute
			}
			gen := fetch.SessionGen()
			s.leases[id] = lease{t: t, until: time.Now().Add(hold), gen: gen}
			c.reply <- &Task{ID: id, Item: types.WorkItem{ID: workID(t.col, t.seed), Collector: t.col, Seed: t.seed}, Session: gen}
			return
		}
	}
	c.reply <- nil
}

// giveBack records what a worker sent for a lent task.
func (s *scheduler) giveBack(ctx context.Context, d remoteDone) {
	l, ok := s.leases[d.id]
	if !ok {
		d.ok <- false
		return
	}
	delete(s.leases, d.id)
	s.remote--
	d.ok <- true
	item := types.WorkItem{ID: workID(l.t.col, l.t.seed), Collector: l.t.col, Seed: l.t.seed}
	meta, err := s.e.Record(item, d.out)
	// The worker's requests count toward the session check, and the check
	// is made here: with all the work remote, no request of this process
	// would make it.
	fetch.AbsorbReport(d.out.Session, d.out.Requests, l.gen == fetch.SessionGen())
	_ = fetch.CheckDue(ctx)
	printItem(ctx, item, 0, meta, err)
	s.handle(finished{tasks: []task{l.t}, metas: []types.RunMeta{meta}, errs: []error{err}})
}

// expire queues again the tasks whose worker went silent.
func (s *scheduler) expire() {
	now := time.Now()
	for id, l := range s.leases {
		if now.After(l.until) {
			delete(s.leases, id)
			s.remote--
			s.inflight--
			s.ran--
			s.enqueue(l.t)
		}
	}
}

// release gives up on lent tasks once the run is stopping: they are not
// done, and azhaq resume runs them.
func (s *scheduler) release() {
	for id := range s.leases {
		delete(s.leases, id)
		s.remote--
		s.inflight--
	}
}

func (s *scheduler) dispatch(ctx context.Context) {
	for s.inflight-s.remote < s.b.Parallel {
		if s.startBatch(ctx) {
			continue
		}
		t, ok := s.next()
		if !ok {
			s.startRetry(ctx)
			return
		}
		s.start(ctx, t)
	}
}

// startRetry runs the cheapest task the budget stopped before, when
// nothing else runs.
func (s *scheduler) startRetry(ctx context.Context) {
	for s.inflight-s.remote == 0 && len(s.retry) > 0 && !egress.Spent() && !s.itemsSpent() {
		t := s.retry[0]
		s.retry = s.retry[1:]
		if s.skip(t) || s.catchAllGate(t) == gateHold {
			s.finish(t)
			s.unpark(t)
			continue
		}
		s.ran++
		s.start(ctx, t)
	}
}

// next pops the next runnable task: seed-origin work first while it is
// within its share of the budget, then fan-out.
func (s *scheduler) next() (task, bool) {
	for p := 0; p < 2; p++ {
		for i := 0; i < len(s.queue[p]); {
			t := s.queue[p][i]
			drop := func() {
				s.queue[p] = slices.Delete(s.queue[p], i, i+1)
				s.finish(t)
				s.unpark(t) // nothing to wait for
			}
			if s.skip(t) {
				drop()
				continue
			}
			switch s.catchAllGate(t) {
			case gateHold:
				drop()
				continue
			case gateWait:
				i++ // its directory's answers have not decided: the others go on
				continue
			}
			if egress.Spent() && s.contacts(t) {
				// It would only be refused: it waits for azhaq resume.
				s.queue[p] = slices.Delete(s.queue[p], i, i+1)
				s.held = append(s.held, t)
				continue
			}
			if s.itemsSpent() {
				return task{}, false
			}
			if p == 0 && s.originSpent() {
				break
			}
			s.queue[p] = slices.Delete(s.queue[p], i, i+1)
			s.ran++
			if p == 0 {
				s.originRan++
			}
			return t, true
		}
	}
	return task{}, false
}

func (s *scheduler) start(ctx context.Context, t task) {
	s.inflight++
	s.flightStart(t)
	s.noteStretch(t)
	item := types.WorkItem{ID: workID(t.col, t.seed), Collector: t.col, Seed: t.seed}
	go func() {
		t0 := time.Now()
		ctx := catalog.WithHints(ctx, func(seeds []types.Seed) {
			s.results <- finished{tasks: []task{t}, metas: []types.RunMeta{{NextHints: seeds}}, errs: []error{nil}, partial: true}
		})
		var meta types.RunMeta
		var err error
		// Run recovers a collector's panic; this catches the rest of the
		// task's own code, so the loop is always answered.
		if perr := guard.Call(func() error { meta, err = s.e.Run(ctx, item); return nil }); perr != nil {
			meta, err = types.RunMeta{ItemID: item.ID, Status: types.StatusError, Error: perr.Error()}, perr
			s.e.failTask(t.seed, t.col, perr)
		}
		printItem(ctx, item, time.Since(t0), meta, err)
		s.results <- finished{tasks: []task{t}, metas: []types.RunMeta{meta}, errs: []error{err}}
	}()
}

// startBatch hands waiting seeds to one idle batch collector.
func (s *scheduler) startBatch(ctx context.Context) bool {
	for name, waiting := range s.batch {
		if len(waiting) == 0 || s.batchBusy[name] >= batchesInFlight {
			continue
		}
		col, _ := s.e.Cat.Get(name)
		size := col.(catalog.Batcher).BatchSize()
		if size <= 0 {
			size = 1
		}
		n := min(len(waiting), size, s.b.MaxNames-s.names)
		if n <= 0 {
			continue
		}
		tasks := append([]task(nil), waiting[:n]...)
		s.batch[name] = waiting[n:]
		s.batchBusy[name]++
		s.names += n
		s.inflight++
		go func() {
			seeds := make([]types.Seed, len(tasks))
			for i, t := range tasks {
				seeds[i] = t.seed
			}
			t0 := time.Now()
			var res []BatchResult
			var err error
			if perr := guard.Call(func() error { res, err = s.e.RunBatch(ctx, name, seeds); return nil }); perr != nil {
				res, err = nil, perr
				for _, sd := range seeds {
					s.e.failTask(sd, name, perr)
				}
			}
			printBatch(ctx, name, len(seeds), time.Since(t0), err)
			byKey := map[string]types.RunMeta{}
			for _, r := range res {
				byKey[seedKey(r.Seed)] = r.Meta
			}
			f := finished{batch: name}
			for _, t := range tasks {
				m, ok := byKey[seedKey(t.seed)]
				if !ok {
					// Already ran in an earlier run on this database, or the
					// batch failed: release whatever waits on it.
					m = types.RunMeta{Status: types.StatusOK}
					switch {
					case ctx.Err() != nil:
						// Stopped while the names waited for their answers:
						// not done, azhaq resume asks them again.
						m.Status = types.StatusCancelled
					case err != nil:
						m.Status = types.StatusError
					}
				}
				f.tasks = append(f.tasks, t)
				f.metas = append(f.metas, m)
				f.errs = append(f.errs, nil)
			}
			s.results <- f
		}()
		return true
	}
	return false
}

func (s *scheduler) handle(f finished) {
	if f.scheme != "" {
		s.schemeAnswered(f.scheme, f.same)
		return
	}
	if f.partial {
		for i, t := range f.tasks {
			for _, h := range f.metas[i].NextHints {
				h = s.markNamed(t, h)
				s.add(h, t.depth+hintStep(h), true)
			}
		}
		return
	}
	s.inflight--
	if f.batch != "" {
		s.batchBusy[f.batch]--
	}
	for i, t := range f.tasks {
		meta, err := f.metas[i], f.errs[i]
		switch {
		case meta.Status == types.StatusCapped:
			// Not done, nor what waits on it: azhaq resume runs them,
			// after the work the budget has not stopped yet.
			if s.e.Store != nil {
				s.stopped = append(s.stopped, store.Stopped{ID: workID(t.col, t.seed), Used: meta.Requests})
			}
		case meta.Status == types.StatusCancelled:
			// Not done, nor what waits on it: azhaq resume runs them.
		case meta.Drop:
			s.finish(t)
			s.drop(seedKey(t.seed), t.col)
		default:
			s.finish(t)
			s.unpark(t)
		}
		s.flightEnd(t)
		s.endStretch(t, meta)
		if err != nil && meta.Status != types.StatusCancelled {
			continue
		}
		for _, h := range meta.NextHints {
			h = s.markNamed(t, h)
			s.add(h, t.depth+hintStep(h), true)
		}
	}
}

// markNamed notes a URL hint a script gave, unless it was queued before: a
// link of a page is the app's own and is always asked, and so is a script
// the run loaded to read. The hint it returns says it was named, so that a
// resume knows.
func (s *scheduler) markNamed(from task, h types.Seed) types.Seed {
	if from.col != "azhaq-js" {
		return h
	}
	seed := normalize.Seed(h)
	if seed.Type != types.TypeURL || seed.Key() == "" || seed.Keys[types.ViaKey] == types.ViaLoaded {
		return h
	}
	if k := seedKey(seed); !s.seen[k] {
		s.named[k] = true
		fetch.NoteNamed(seed.Key())
		if seed.Keys[types.ViaKey] == "" {
			h = normalize.Seed(h)
			h.Keys[types.ViaKey] = types.ViaScript
		}
	}
	return h
}

// A task's turn under the catch-all rule.
type gateAnswer int

const (
	gateAsk  gateAnswer = iota // ask it
	gateHold                   // do not ask it: its directory answers every path with one page
	gateWait                   // ask it later, when the directory's answers have decided
)

// namedFlight is the named URLs being asked, by directory: the paths of a
// directory whose answers have not settled the rule go one at a time.
type namedFlight struct {
	tasks map[string]int  // seed key → its tasks running
	dir   map[string]int  // origin and directory → seeds running
	began map[string]bool // seed keys that started: their other tasks go on
}

func newNamedFlight() namedFlight {
	return namedFlight{tasks: map[string]int{}, dir: map[string]int{}, began: map[string]bool{}}
}

// namedWhere is the directory of a task's URL (origin and path, as the
// controls are kept), when the rule concerns it: a URL a script named, with a
// catch-all stop set.
func (s *scheduler) namedWhere(t task) (k, dir string, st fetch.DirState, ok bool) {
	if s.b.CatchAllStop <= 0 || t.seed.Type != types.TypeURL {
		return
	}
	k = seedKey(t.seed)
	if !s.named[k] {
		return
	}
	st, dir = fetch.CatchAllDir(t.seed.Key(), s.b.CatchAllStop)
	return k, dir, st, st != fetch.DirNone
}

// catchAllGate says what a task does under the catch-all rule: a URL a
// script named is held when Budgets.CatchAllStop of its directory's
// script-named paths answered with the page every unknown path gets, before
// as many answered anything else (fetch.CatchAllHeld). Until then the
// directory's paths go one at a time, so that a loaded machine sends what an
// idle one does; a directory whose paths answer for themselves is asked
// whole. A held URL stays in the map as not requested, with the reason.
func (s *scheduler) catchAllGate(t task) gateAnswer {
	k, dir, st, ok := s.namedWhere(t)
	if !ok || s.flight.began[k] {
		return gateAsk
	}
	if s.catchHeld[k] {
		return gateHold
	}
	switch {
	case st == fetch.DirHeld:
		s.catchHeld[k] = true
		fetch.NoteHeld(t.seed.Key())
		s.e.noteSkip(t.seed, CatchAllHeldReason)
		return gateHold
	case st != fetch.DirReal && s.flight.dir[dir] > 0:
		return gateWait
	}
	return gateAsk
}

// flightStart notes a task of a named URL running.
func (s *scheduler) flightStart(t task) {
	k, dir, _, ok := s.namedWhere(t)
	if !ok {
		return
	}
	f := &s.flight
	if f.tasks[k] == 0 {
		f.dir[dir]++
	}
	f.tasks[k]++
	f.began[k] = true
}

// flightEnd notes one ended.
func (s *scheduler) flightEnd(t task) {
	k, dir, _, ok := s.namedWhere(t)
	f := &s.flight
	if !ok || f.tasks[k] == 0 {
		return
	}
	if f.tasks[k]--; f.tasks[k] == 0 {
		f.dir[dir]--
	}
}

// caps says which limits of the run held work back, and how much.
func (s *scheduler) caps() Caps {
	var c Caps
	if s.itemsSpent() {
		for p := range s.queue {
			for _, t := range s.queue[p] {
				if !s.skip(t) {
					c.ItemsLeft++
				}
			}
		}
		c.ItemsLeft += len(s.retry)
	}
	if s.b.MaxNames > 0 && s.names >= s.b.MaxNames {
		for _, waiting := range s.batch {
			c.NamesLeft += len(waiting)
		}
	}
	for _, seed := range s.beyond {
		if s.seen[seedKey(seed)] {
			continue
		}
		switch seed.Type {
		case types.TypeURL:
			c.DepthURLs++
		case types.TypeHostname:
			c.DepthNames++
		}
	}
	return c
}

// leftover is every seed with work that did not run: over budget, or
// found past the depth limit.
func (s *scheduler) leftover() []types.Seed {
	var out []types.Seed
	seen := map[string]bool{}
	put := func(seed types.Seed) {
		k := seedKey(seed)
		if !seen[k] {
			seen[k] = true
			out = append(out, seed)
		}
	}
	for p := range s.queue {
		for _, t := range s.queue[p] {
			if !s.skip(t) {
				put(t.seed)
			}
		}
	}
	for _, waiting := range s.batch {
		for _, t := range waiting {
			put(t.seed)
		}
	}
	for _, t := range append(s.held, s.retry...) {
		put(t.seed)
	}
	for _, waiting := range s.parked {
		for _, t := range waiting {
			put(t.seed)
		}
	}
	for _, seed := range s.beyond {
		if !s.seen[seedKey(seed)] {
			put(seed)
		}
	}
	for _, held := range s.waiting {
		for _, h := range held {
			put(h.seed)
		}
	}
	return out
}

func printBatch(ctx context.Context, name string, n int, d time.Duration, err error) {
	if isQuiet(ctx) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ! %s %d seeds: %s\n", name, n, ShortError(err.Error()))
		return
	}
	if p, _ := ctx.Value(progressKey{}).(*progress); p != nil && p.verbose {
		fmt.Fprintf(os.Stderr, "  . %s %d seeds  %s\n", name, n, d.Round(time.Millisecond))
	}
}

// hintStep is how much deeper a hint goes: none for the same target under
// another scheme (types.SameTargetKey), where a redirect led
// (types.RedirectKey) or a well-known location of the same origin
// (types.KnownLocationKey), one otherwise.
func hintStep(h types.Seed) int {
	if h.Keys[types.SameTargetKey] != "" || h.Keys[types.RedirectKey] != "" || h.Keys[types.KnownLocationKey] != "" {
		return 0
	}
	return 1
}
