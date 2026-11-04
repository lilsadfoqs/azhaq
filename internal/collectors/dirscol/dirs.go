// Package dirscol guesses paths on a web service from a wordlist (-dirs,
// active): ffuf and feroxbuster's job. Each directory is calibrated first
// with paths that cannot exist, so a server that answers everything
// (single-page apps, soft 404s, login redirects) does not flood the results.
package dirscol

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"hash"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/internal/limit"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/pagesim"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
	"github.com/lilsadfoqs/azhaq/types"
)

const Name = "azhaq-dirs"

// common is SecLists' Discovery/Web-Content/common.txt (MIT, Daniel
// Miessler; commit 61060549893d61b428d2184bb719abf23b4b3f13), the list a
// sweep uses when the user gives none. It is read at build time: nothing
// is downloaded when azhaq runs. Three entries are left out: they carry an
// outside address (render?url=https://www.google.com, render/https://www.google.com,
// dns-query?name=google.com&type=A) that makes the target fetch or look it
// up, which a path is not.
//
//go:embed common.txt
var common string

// Builtin names the built-in list where a wordlist file is asked for
// (-dirs @common), so a run that used it can be resumed.
const Builtin = "@common"

// DefaultWords is the built-in wordlist, one word per element.
func DefaultWords() []string {
	var out []string
	for _, l := range strings.Split(common, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// WordCount is how many words DefaultWords has, counted without building
// the list (a flag's help names it, and help is built on every start).
func WordCount() int {
	n := 0
	for rest := common; rest != ""; {
		var l string
		l, rest, _ = strings.Cut(rest, "\n")
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// Options shape a sweep.
type Options struct {
	Words      []string
	Extensions []string // "php" also tries word.php
	Depth      int      // directory levels to descend; 1 is the start only
	Threads    int      // requests in flight per service
	Rate       float64  // requests per second per host; 0: no limit
	// Set holds the matchers and filters (-mc -ms … -fr). Nil: the default
	// -mc. A Set with filters but no matcher reports nothing: give it the
	// default status matcher (DefaultStatus) first.
	Set *fuzz.Set
	// NoCalibration skips the guesses at paths that cannot exist (-ac=false):
	// the filters are the user's alone.
	NoCalibration bool
	// UserWords says the words are the user's own wordlist: every one is
	// asked, as ffuf does. With the built-in list a word whose own name
	// declares a state change (logout, reset, delete, ...) is held back
	// unless -send-state-changing is given, and listed as skipped.
	UserWords bool
}

// DefaultStatus is ffuf's default -mc.
const DefaultStatus = "200-299,301,302,307,401,403,405,500"

// NewSet is a Set with the default status matcher, for the caller to add
// the user's filters to; when the user gave a matcher of their own, use a
// fresh fuzz.NewSet(nil) instead, as ffuf does.
func NewSet() *fuzz.Set {
	set := fuzz.NewSet(nil)
	_ = set.AddMatcher("status", DefaultStatus)
	return set
}

type Collector struct {
	Client *http.Client
	Opts   Options

	limiter  *limit.Limiter
	swept    sync.Map // directory URL → true
	needBody bool     // a pattern reads the body
}

func New(client *http.Client, o Options) *Collector {
	if o.Depth <= 0 {
		o.Depth = 1
	}
	if o.Threads <= 0 {
		o.Threads = 40
	}
	if o.Rate <= 0 {
		o.Rate = 1e6 // no pace but the threads', as ffuf
	}
	if o.Set == nil {
		o.Set = NewSet()
	}
	c := *fetch.Client(client)
	// Redirects are answers here: a directory is the path that redirects
	// to itself with a slash.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// One connection kept per thread, as ffuf does: the default keeps two,
	// and a sweep would open a connection (on https, a handshake) for
	// about every third request.
	c = *egress.Tweak(&c, func(tr *http.Transport) {
		tr.MaxIdleConnsPerHost = max(o.Threads, 2)
		tr.MaxIdleConns = 2 * max(o.Threads, 2)
	})
	return &Collector{Client: &c, Opts: o, limiter: limit.New(o.Rate, max(1, int(o.Rate/10))), needBody: o.Set.NeedBody()}
}

// dirPath is the directory a URL path sweeps: the path with a slash at
// the end.
func dirPath(p string) string {
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func (c *Collector) Name() string { return Name }

// Standing: a hit is checked against the directory's calibration before
// it is reported, so a run the budget stops keeps the hits it found.
func (c *Collector) Standing() bool { return true }

// Forget lets the sweeps at and under raw run again, after a session that
// ended made their answers wrong (catalog.Forgetter).
func (c *Collector) Forget(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	base := u.Scheme + "://" + u.Host + dirPath(u.Path)
	c.swept.Range(func(k, _ any) bool {
		if strings.HasPrefix(k.(string), base) {
			c.swept.Delete(k)
		}
		return true
	})
}

// Info: many requests to the target; needs -dirs and -allow, and waits for
// the HTTP collector so it starts from a service that answered.
func (c *Collector) Info() catalog.Info {
	return catalog.Info{Kind: catalog.Active, Flag: "dirs", After: "azhaq-http", Redo: true}
}

func (c *Collector) Inputs() []types.SeedType { return []types.SeedType{types.TypeURL} }

func (c *Collector) Outputs() []string { return []string{"url"} }

// Skip: a sweep starts at a URL the user gave, from its path, or at a
// service's front page; deeper directories are reached by recursion
// inside the sweep.
func (c *Collector) Skip(seed types.Seed) bool {
	if len(c.Opts.Words) == 0 {
		return true
	}
	raw, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	if seed.Keys[types.StartKey] != "" {
		return false
	}
	return (u.Path != "" && u.Path != "/") || u.RawQuery != ""
}

// hit is one guessed path that answered.
type hit struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
	Words    int    `json:"words"`
	Lines    int    `json:"lines"`
	Location string `json:"location,omitempty"`
	// Control is set for a hit whose answer is, byte for byte, what its
	// directory gave a name that cannot exist: the hit says nothing of a
	// route, and the map folds it.
	Control *fetch.Control `json:"-"`
}

func (c *Collector) Run(ctx context.Context, seed types.Seed, emit func(types.Observation) error) (types.RunMeta, error) {
	start, err := normalize.URL(seed.Keys["url"])
	if err != nil {
		return types.RunMeta{Status: types.StatusError, Error: err.Error()}, err
	}
	u, _ := url.Parse(start)
	base := u.Scheme + "://" + u.Host + dirPath(u.Path)
	// Which words are held back is decided here, by the word alone (see
	// HeldWords): the base path they are asked under says nothing about them.
	ctx = egress.WithAsked(ctx)
	meta := types.RunMeta{Status: types.StatusOK}
	queue := []dirLevel{{url: base, depth: 1}}
	var all []hit
	var skipped []heldURL // guesses not sent: nobody saw them exist, so they are no URLs of the map
	requests, filtered, failed, limited := 0, 0, 0, 0
	// Each hit is kept as it is found, as ffuf prints it: a run stopped by
	// Ctrl-C or the budget keeps what it found so far. Hits are handed over
	// in batches; the engine writes a batch in one transaction.
	batch := types.BatchEmitFrom(ctx)
	found := func(hs []hit) error {
		obs := make([]types.Observation, 0, len(hs))
		for _, h := range hs {
			row := map[string]any{"url": h.URL, "via": "dirs", "status": h.Status, "length": h.Length, "words": h.Words, "lines": h.Lines}
			if h.Location != "" {
				row["location"] = h.Location
			}
			if h.Control != nil {
				row["catchall"], row["control"], row["control_exact"] = true, h.Control, true
			}
			raw, _ := json.Marshal(row)
			obs = append(obs, types.Observation{Collector: Name, Source: base, Kind: "url", Payload: raw, Confidence: 0.8, ObservedAt: time.Now().UTC()})
		}
		var err error
		if batch != nil {
			err = batch(obs)
		} else {
			for _, o := range obs {
				if err = emit(o); err != nil {
					break
				}
			}
		}
		if err != nil {
			return err
		}
		meta.EmitCount += len(hs)
		for _, h := range hs {
			meta.NextHints = append(meta.NextHints, types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": h.URL}})
		}
		return nil
	}
	var emitErr error
	var note sweepNote
	for len(queue) > 0 && ctx.Err() == nil && emitErr == nil {
		d := queue[0]
		queue = queue[1:]
		if _, done := c.swept.LoadOrStore(d.url, true); done {
			continue
		}
		hits, n, f, x, lim, held, spent, err := c.sweep(ctx, d.url, &note, found)
		if err != nil {
			emitErr = err
		}
		if spent {
			// The sweep is redone whole by azhaq resume; what it found is
			// kept, and found again.
			c.swept.Delete(d.url)
			return types.RunMeta{Status: types.StatusCapped, EmitCount: meta.EmitCount, NextHints: meta.NextHints}, neterr.ErrBudget
		}
		requests += n
		filtered += f
		failed += x
		limited += lim
		all = append(all, hits...)
		skipped = append(skipped, held...)
		for _, h := range hits {
			if d.depth < c.Opts.Depth && isDir(h) && h.Control == nil {
				queue = append(queue, dirLevel{url: strings.TrimSuffix(h.URL, "/") + "/", depth: d.depth + 1})
			}
		}
	}
	if emitErr != nil {
		return meta, emitErr
	}
	if ctx.Err() != nil {
		return types.RunMeta{Status: types.StatusCancelled, EmitCount: meta.EmitCount, NextHints: meta.NextHints}, ctx.Err()
	}
	summary, _ := json.Marshal(map[string]any{
		"base": base, "words": len(c.Opts.Words), "extensions": c.Opts.Extensions, "requests": requests,
		"hits": len(all), "filtered": filtered, "failed": failed, "rate_limited": limited, "depth": c.Opts.Depth,
		"held": note.shaped.Load(), "unfiltered": note.unfiltered(),
		"controls": note.controls.Load(), "folded": note.folded.Load(),
	})
	if err := emit(types.Observation{Collector: Name, Source: base, Kind: "dirs", Payload: summary, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
		return meta, err
	}
	meta.EmitCount++
	byRule := map[string][]string{}
	var rules []string
	for _, h := range skipped {
		if _, ok := byRule[h.rule]; !ok {
			rules = append(rules, h.rule)
		}
		byRule[h.rule] = append(byRule[h.rule], h.url)
	}
	for _, rule := range rules {
		raw, _ := json.Marshal(map[string]any{"skipped": egress.DenyReason(rule), "urls": byRule[rule]})
		if err := emit(types.Observation{Collector: Name, Source: base, Kind: "skipped", Payload: raw, Confidence: 0.9, ObservedAt: time.Now().UTC()}); err != nil {
			return meta, err
		}
		meta.EmitCount++
	}
	return meta, nil
}

// heldWord is the word that makes the built-in list's guess t a state
// change by its own name, while the run holds those back; "" for any guess
// of the user's own wordlist.
func (c *Collector) heldWord(t string) string {
	if c.Opts.UserWords || !egress.Current().Holding() {
		return ""
	}
	return statechange.OfPath("/" + t)
}

// HeldWords is how many of the requests the built-in list's words and
// extensions make would be held back as state-changing: the number a plan and
// an estimate leave out. Every word is asked bare and with each extension.
func HeldWords(words, exts []string) int {
	n := 0
	for _, w := range words {
		w = strings.TrimPrefix(strings.TrimSpace(w), "/")
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		forms := []string{w}
		for _, ext := range exts {
			forms = append(forms, w+"."+strings.TrimPrefix(ext, "."))
		}
		for _, t := range forms {
			if statechange.OfPath("/"+t) != "" {
				n++
			}
		}
	}
	return n
}

// heldURL is a word's URL a -deny-path rule keeps out, and the rule.
type heldURL struct{ url, rule string }

type dirLevel struct {
	url   string
	depth int
}

// isDir: a path that redirects to itself with a slash, as servers do for
// directories.
func isDir(h hit) bool {
	if h.Location == "" {
		return false
	}
	return strings.TrimSuffix(h.Location, "/") == h.URL || strings.HasSuffix(h.Location, strings.TrimPrefix(h.URL, schemeHost(h.URL))+"/")
}

func schemeHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// maxPending is how many hits wait for the writer before the requests
// slow down to its pace; the writer takes up to maxBatch of them, or a
// batchEvery's worth, at a time.
const (
	maxPending = 4096
	maxBatch   = 2048
	batchEvery = 100 * time.Millisecond
)

// sweep guesses every word (and word.ext) under dir, handing the hits to
// found in batches from one goroutine, so no request waits for a write;
// held lists the URLs not sent because a -deny-path rule keeps them out;
// spent says the request budget ran out before it was
// through; limited counts the answers that were 429, which no default
// matcher keeps; err is what found returned.
func (c *Collector) sweep(ctx context.Context, dir string, note *sweepNote, found func([]hit) error) (_ []hit, _ int, _ int, failed, limited int, held []heldURL, spent bool, err error) {
	host := schemeHost(dir)
	cal := calibration{echo: map[int]bool{}, vary: map[int]bool{}}
	if !c.Opts.NoCalibration {
		var dead error
		if cal, dead = c.calibrate(ctx, dir, host); dead != nil {
			return nil, 0, 0, 0, 0, nil, false, dead
		}
		note.loose(dir, cal.unfiltered)
	}
	var targets []string
	for _, w := range c.Opts.Words {
		// An empty word asks for the base URL itself, as in ffuf.
		blank := w == ""
		w = strings.TrimPrefix(strings.TrimSpace(w), "/")
		if (w == "" && !blank) || strings.HasPrefix(w, "#") {
			continue
		}
		words := []string{w}
		for _, ext := range c.Opts.Extensions {
			words = append(words, w+"."+strings.TrimPrefix(ext, "."))
		}
		for _, t := range words {
			if rule := egress.DeniedBy(dir + escapeWord(t)); rule != "" {
				held = append(held, heldURL{dir + escapeWord(t), rule})
				continue
			}
			if w := c.heldWord(t); w != "" {
				held = append(held, heldURL{dir + escapeWord(t), neterr.HeldRule(w)})
				continue
			}
			targets = append(targets, t)
		}
	}
	var hits []hit
	var filtered, nfailed, nlimited atomic.Int64
	var out, halt atomic.Bool
	var inDirs []exactHit // hits for words in a directory of their own, judged when the sweep is through
	var inDirsMu sync.Mutex
	pending := make(chan hit, maxPending)
	written := make(chan struct{})
	go func() {
		defer guard.Recover(ctx)
		defer close(written)
		for h := range pending {
			batch := []hit{h}
			// A moment's hits go to the store together: a commit costs more
			// than the hit.
			wait := time.NewTimer(batchEvery)
		fill:
			for len(batch) < maxBatch {
				select {
				case h, ok := <-pending:
					if !ok {
						break fill
					}
					batch = append(batch, h)
				case <-wait.C:
					break fill
				}
			}
			wait.Stop()
			hits = append(hits, batch...)
			if err == nil {
				if err = found(batch); err != nil {
					halt.Store(true)
				}
			}
		}
	}()
	// ask sends one word and judges the answer; it returns the error of a
	// request that got none.
	ask := func(word string) error {
		target := dir + escapeWord(word)
		nested := !c.Opts.NoCalibration && inOwnDir(word)
		r, err := c.get(ctx, target, "", len(cal.shapes) > 0, nested)
		if errors.Is(err, neterr.ErrBudget) {
			out.Store(true)
		}
		if err != nil {
			if !out.Load() && ctx.Err() == nil && !errors.Is(err, neterr.ErrDenied) {
				nfailed.Add(1)
			}
			return err
		}
		if r.Status == http.StatusTooManyRequests {
			nlimited.Add(1)
		}
		if !c.matches(r) {
			return nil
		}
		if by := cal.explains(r, word); by != byNothing {
			filtered.Add(1)
			if by == byShape {
				note.shaped.Add(1)
			}
			return nil
		}
		h := hit{URL: target, Status: r.Status, Length: r.Length, Words: r.Words, Lines: r.Lines, Location: r.Location}
		if nested {
			inDirsMu.Lock()
			inDirs = append(inDirs, exactHit{h, r})
			inDirsMu.Unlock()
			return nil
		}
		pending <- h
		return nil
	}
	// With no calibration the first words ask whether the service answers
	// at all, so a dead one is one failed request, not the whole list, and
	// no request is spent on a check apart from the sweep.
	var dead error
	first := 0
	if c.Opts.NoCalibration {
		var lost error
		for first < min(2, len(targets)) && ctx.Err() == nil && !out.Load() {
			if c.pace(ctx, host, dir+escapeWord(targets[first])) != nil {
				break
			}
			err := ask(targets[first])
			first++
			if err == nil || errors.Is(err, neterr.ErrBudget) || errors.Is(err, neterr.ErrDenied) || ctx.Err() != nil {
				lost = nil
				break
			}
			lost = err
		}
		dead = lost
	}
	sem := make(chan struct{}, c.Opts.Threads)
	var wg sync.WaitGroup
	for _, t := range targets[first:] {
		if ctx.Err() != nil || out.Load() || halt.Load() || dead != nil {
			break
		}
		if err := c.pace(ctx, host, dir+escapeWord(t)); err != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(word string) {
			defer guard.Recover(ctx)
			defer wg.Done()
			defer func() { <-sem }()
			_ = ask(word)
		}(t)
	}
	wg.Wait()
	// The hits in a directory the sweep did not start in are judged by an
	// answer of that directory, and only then handed on.
	for _, h := range c.judgeInDirs(ctx, host, inDirs, note, &out, &halt) {
		pending <- h
	}
	close(pending)
	<-written
	if dead != nil && err == nil {
		err = dead
	}
	return hits, len(targets), int(filtered.Load()), int(nfailed.Load()), int(nlimited.Load()), held, out.Load(), err
}

// exactHit is a hit with the answer it got.
type exactHit struct {
	hit hit
	r   response
}

// inOwnDir says a word names a path in a directory of its own (api/users),
// not one of the swept directory itself (users, or admin/, which is the
// directory).
func inOwnDir(word string) bool {
	path, _, _ := strings.Cut(word, "?")
	return strings.Contains(strings.TrimSuffix(path, "/"), "/")
}

// dirOf is the directory a URL's path is in, with its slash.
func dirOf(target string) string {
	path, _, _ := strings.Cut(target, "?")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i+1]
	}
	return path
}

// judgeInDirs gives the hits found in directories the sweep was not started
// in, each marked with the control of its directory when its answer is
// that control's, byte for byte. A directory that holds two hits or more is
// asked one name that cannot exist, at the sweep's pace and counted like its
// requests; the hit of a directory that holds only one is kept as it is.
// When the budget runs out, the run is stopped or a control fails to answer,
// the hits are handed on unmarked: they were found.
func (c *Collector) judgeInDirs(ctx context.Context, host string, hs []exactHit, note *sweepNote, out, halt *atomic.Bool) []hit {
	byDir := map[string][]int{}
	var dirs []string
	for i, h := range hs {
		d := dirOf(h.hit.URL)
		if _, ok := byDir[d]; !ok {
			dirs = append(dirs, d)
		}
		byDir[d] = append(byDir[d], i)
	}
	out2 := make([]hit, len(hs))
	for i, h := range hs {
		out2[i] = h.hit
	}
	for _, d := range dirs {
		idx := byDir[d]
		if len(idx) < 2 || ctx.Err() != nil || out.Load() || halt.Load() {
			continue
		}
		name := fetch.ProbeName("dirs control " + d)
		target := d + name
		if c.pace(ctx, host, target) != nil {
			continue
		}
		ctl, err := c.get(ctx, target, name, false, true)
		if errors.Is(err, neterr.ErrBudget) {
			out.Store(true)
		}
		if err != nil {
			continue
		}
		note.controls.Add(1)
		ref := &fetch.Control{URL: target, Status: ctl.Status, Size: ctl.Length}
		for _, i := range idx {
			if ctl.sameAs(hs[i].r) {
				out2[i].Control = ref
				note.folded.Add(1)
			}
		}
	}
	return out2
}

// sameAs says r is the answer c is, byte for byte: the same status and the
// same body (or, for a redirect, the same Location), once the path each was
// asked for is taken out of it.
func (c response) sameAs(r response) bool {
	if c.Status != r.Status {
		return false
	}
	if c.Status >= 300 && c.Status < 400 {
		return c.Loc != "" && c.Loc == r.Loc
	}
	return c.Sum != "" && c.Sum == r.Sum || c.Free != "" && c.Free == r.Free
}

// escapeWord puts a word in a URL as ffuf does: a "?" starts the query
// (SecLists lists have render?url=…), the path is escaped by segment.
func escapeWord(w string) string {
	path, query, hasQuery := strings.Cut(w, "?")
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	out := strings.Join(parts, "/")
	if hasQuery {
		out += "?" + strings.NewReplacer(" ", "%20", "#", "%23").Replace(query)
	}
	return out
}

// matches says whether the user's matchers and filters keep r.
func (c *Collector) matches(r response) bool {
	return c.Opts.Set.Matches(&fuzz.Response{
		Status: r.Status, Header: r.Header, Body: r.Body,
		Length: int64(r.Length), Words: int64(r.Words), Lines: int64(r.Lines),
	})
}

// errCutOff: the connection ended before the body did.
var errCutOff = errors.New("answer cut off")

// response is what the sweep compares: the body only for a pattern, and
// never kept past the answer.
type response struct {
	Status, Length, Words, Lines int
	Location                     string
	Echo                         bool          `json:",omitempty"` // calibration: the body names the path asked
	Page                         *pagesim.Page `json:",omitempty"` // what the body is, when calibration needs the shape of pages
	// Sum, Free and Loc say what the answer is byte for byte, for a hit in a
	// directory of its own: the sum of the body, the sum and the Location with
	// the path asked taken out (an error page that echoes it). Empty when
	// they were not asked for.
	Sum    string      `json:",omitempty"`
	Free   string      `json:",omitempty"`
	Loc    string      `json:",omitempty"`
	Header http.Header `json:"-"`
	Body   []byte      `json:"-"`
}

// pace waits for a pace slot before target is asked, unless its answer is
// stored: get answers from the memo without a request, and a resume does
// not spend -rate on what it already has.
func (c *Collector) pace(ctx context.Context, host, target string) error {
	if c.recalled(target) {
		return ctx.Err()
	}
	return c.limiter.Wait(ctx, host)
}

// recalled says an answer to target is stored in the run's memos.
func (c *Collector) recalled(target string) bool {
	if fetch.Memos == nil || c.needBody {
		return false
	}
	raw, ok := fetch.Memos.Recall("dirs " + target)
	var r response
	return ok && json.Unmarshal(raw, &r) == nil
}

// get asks for target. probe, set for calibration, is the name asked: the
// answer says whether its body repeats it.
func (c *Collector) get(ctx context.Context, target, probe string, page, exact bool) (response, error) {
	// A guess the run made before it was stopped is not sent again (not
	// with a pattern: the memo holds no body).
	memo := fetch.Memos != nil && !c.needBody
	if memo {
		if raw, ok := fetch.Memos.Recall("dirs " + target); ok {
			var r response
			if json.Unmarshal(raw, &r) == nil {
				return r, nil
			}
		}
	}
	r, err := c.send(ctx, target, probe, page, exact)
	if errors.Is(err, errCutOff) && ctx.Err() == nil {
		r, err = c.send(ctx, target, probe, page, exact)
	}
	if err == nil && memo {
		if raw, err := json.Marshal(r); err == nil {
			fetch.Memos.Remember("dirs "+target, raw)
		}
	}
	return r, err
}

// maxBody is the most of an answer that is read: its length is the whole
// body's up to here.
const maxBody = 64 << 20

// keepBody is the most of a body kept, for a pattern or an echo check.
const keepBody = 1 << 20

var chunks = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

func (c *Collector) send(ctx context.Context, target, probe string, page, exact bool) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return response{}, err
	}
	fetch.ApplySweepHeaders(req)
	if err := egress.Spend(ctx); err != nil {
		return response{}, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	// Counted as it streams, as ffuf counts the body: words are spaces+1
	// and lines newlines+1 of the whole of it.
	r := response{Status: resp.StatusCode, Location: resp.Header.Get("Location"), Words: 1, Lines: 1}
	keep := c.needBody || probe != "" || page || exact
	var kept []byte
	var sum hash.Hash
	if exact {
		sum = sha256.New()
	}
	buf := chunks.Get().(*[]byte)
	defer chunks.Put(buf)
	for r.Length < maxBody {
		n, err := resp.Body.Read(*buf)
		if n > 0 {
			chunk := (*buf)[:n]
			r.Words += bytes.Count(chunk, []byte{' '})
			r.Lines += bytes.Count(chunk, []byte{'\n'})
			r.Length += n
			if sum != nil {
				sum.Write(chunk)
			}
			if keep && len(kept) < keepBody {
				kept = append(kept, chunk[:min(n, keepBody-len(kept))]...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			// A body cut off is not an answer: its length would be a size
			// calibration never saw, and the page would pass as a hit.
			return response{}, fmt.Errorf("%w: %v", errCutOff, err)
		}
	}
	if c.needBody {
		r.Header, r.Body = resp.Header, kept
	}
	if probe != "" {
		r.Echo = bytes.Contains(kept, []byte(probe))
	}
	if (probe != "" || page) && len(kept) > 0 {
		p := pagesim.Of(kept)
		r.Page = &p
	}
	if exact {
		r.Sum = hex.EncodeToString(sum.Sum(nil)[:8])
		if len(kept) == r.Length { // the whole body, to take the path out of
			free := sha256.Sum256([]byte(fetch.EchoFree(target, string(kept))))
			r.Free = hex.EncodeToString(free[:8])
		}
		r.Loc = fetch.EchoFree(target, r.Location)
	}
	return r, nil
}

// calibration holds what a directory answers for paths that cannot exist.
type calibration struct {
	base   []response
	echo   map[int]bool          // statuses whose body or redirect echoes the path
	vary   map[int]bool          // statuses whose answers differ in size
	shapes map[int]pagesim.Shape // statuses whose answers differ in every number but are one page
	// unfiltered: statuses whose answers the user's matchers keep and that
	// share no size, no word and line counts and no page: nothing tells
	// them from a path that exists.
	unfiltered []int
}

// sweepNote is what a run's sweeps say of calibration beyond the paths:
// the answers held back for being the calibration's page, and the
// directories where calibration could filter nothing.
type sweepNote struct {
	shaped   atomic.Int64
	controls atomic.Int64 // requests for a name that cannot exist, one for each directory hits were found in
	folded   atomic.Int64 // hits whose answer was the control's own
	mu       sync.Mutex
	dirs     []string
}

func (n *sweepNote) loose(dir string, statuses []int) {
	if len(statuses) == 0 {
		return
	}
	n.mu.Lock()
	n.dirs = append(n.dirs, dir)
	n.mu.Unlock()
}

func (n *sweepNote) unfiltered() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.dirs)
}

// CalibrationProbes is how many requests calibrating one directory sends:
// the four shapes and one for each extension (see calibrate).
func CalibrationProbes(extensions int) int { return 4 + extensions }

// calibrate asks for random names of the shapes ffuf's -ac uses (a word,
// admin…, .htaccess…, a directory) and one per extension, at the sweep's
// pace. A file that exists keeps its place even when its content equals
// the catch-all page.
func (c *Collector) calibrate(ctx context.Context, dir, host string) (cal calibration, dead error) {
	cal = calibration{echo: map[int]bool{}, vary: map[int]bool{}}
	probes := []string{randWord(0), randWord(1), randWord(2), randWord(3)}
	shapes := []string{probes[0], "admin" + probes[1], ".htaccess" + probes[2], probes[3] + "/"}
	for _, ext := range c.Opts.Extensions {
		p := randWord(len(probes))
		probes = append(probes, p)
		shapes = append(shapes, p+"."+strings.TrimPrefix(ext, "."))
	}
	// Asked together, up to the sweep's threads (a round trip, not one per
	// shape), and read in the order of the shapes.
	type answer struct {
		r   response
		err error
	}
	answers := make([]answer, len(shapes))
	sem := make(chan struct{}, max(1, min(c.Opts.Threads, len(shapes))))
	var wg sync.WaitGroup
	for i, s := range shapes {
		if c.pace(ctx, host, dir+s) != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer guard.Recover(ctx)
			defer wg.Done()
			defer func() { <-sem }()
			r, err := c.get(ctx, dir+s, probes[i], false, false)
			answers[i] = answer{r, err}
		}()
	}
	wg.Wait()
	// None of them answered: the service does not, and the sweep would
	// ask every word for nothing.
	var lost error
	for _, a := range answers {
		if a.err == nil {
			lost = nil
			break
		}
		if lost == nil && !errors.Is(a.err, neterr.ErrBudget) && !errors.Is(a.err, neterr.ErrDenied) && ctx.Err() == nil {
			lost = a.err
		}
	}
	for i, a := range answers {
		if a.err != nil {
			continue
		}
		r := a.r
		for _, b := range cal.base {
			if b.Status == r.Status && b.Length != r.Length {
				cal.vary[r.Status] = true
			}
		}
		cal.base = append(cal.base, r)
		if r.Echo || strings.Contains(r.Location, strings.TrimSuffix(probes[i], "/")) {
			cal.echo[r.Status] = true
		}
	}
	c.learn(&cal)
	return cal, lost
}

// learn reads the page the answers of a status are when their sizes differ
// and nothing else they count is shared, and notes the statuses where
// nothing tells them from a path that exists.
func (c *Collector) learn(cal *calibration) {
	by := map[int][]response{}
	var order []int
	for _, r := range cal.base {
		if _, ok := by[r.Status]; !ok {
			order = append(order, r.Status)
		}
		by[r.Status] = append(by[r.Status], r)
	}
	for _, st := range order {
		rs := by[st]
		if len(rs) < 2 || !cal.vary[st] || !slices.ContainsFunc(rs, c.matches) {
			continue
		}
		var pages []pagesim.Page
		for _, r := range rs {
			if r.Page != nil {
				pages = append(pages, *r.Page)
			}
		}
		if len(pages) == len(rs) {
			if shape, ok := pagesim.Learn(pages); ok {
				if cal.shapes == nil {
					cal.shapes = map[int]pagesim.Shape{}
				}
				cal.shapes[st] = shape
				continue
			}
		}
		if sharesCount(rs) || cal.echo[st] && sharesCountAll(rs) {
			continue // explains: the same word and line counts say so
		}
		cal.unfiltered = append(cal.unfiltered, st)
	}
}

// sharesCount: some two answers have the same word and line counts (what
// explains takes for a page of that size's family).
func sharesCount(rs []response) bool {
	for i, a := range rs {
		for _, b := range rs[i+1:] {
			if a.Words == b.Words && a.Lines == b.Lines {
				return true
			}
		}
	}
	return false
}

// sharesCountAll: every answer has the same word and line counts.
func sharesCountAll(rs []response) bool {
	for _, r := range rs[1:] {
		if r.Words != rs[0].Words || r.Lines != rs[0].Lines {
			return false
		}
	}
	return true
}

// explains is true when r looks like an answer to a path that does not
// exist: same status as a calibration answer and the same size, as ffuf
// takes it. Where the calibration answers differ in size among themselves
// (a page that names the path, a counter) the size cannot tell, and the
// same word and line counts do, and, where the body repeats the path, a
// size that differs by what the path's length adds. A redirect is
// explained when it echoes the path the way calibration did, or goes where
// they went.
func (cal calibration) explains(r response, word string) explainedBy {
	for _, b := range cal.base {
		if r.Status != b.Status {
			continue
		}
		if r.Length == b.Length {
			return bySize
		}
		if cal.vary[b.Status] && r.Words == b.Words && r.Lines == b.Lines {
			return bySize
		}
		// Bodies that echo the path differ by the path's length.
		if cal.echo[b.Status] && r.Words == b.Words && r.Lines == b.Lines && abs(r.Length-b.Length) <= 2*len(word)+32 {
			return bySize
		}
		if r.Location != "" && b.Location != "" && cal.echo[r.Status] && strings.Contains(r.Location, word) {
			return bySize
		}
		if r.Location != "" && r.Location == b.Location {
			return bySize
		}
	}
	// A page that is a different size each time: by what it is.
	if shape, ok := cal.shapes[r.Status]; ok && r.Page != nil && shape.Like(*r.Page) {
		return byShape
	}
	return byNothing
}

// explainedBy says what made an answer the answer to a path that does not
// exist.
type explainedBy int

const (
	byNothing explainedBy = iota
	bySize                // a count the calibration answers share
	byShape               // the title, tags and words the calibration answers share
)

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// randWord is the name of the n-th calibration probe: fixed within a run, so
// a resumed sweep asks the names the stopped one did and finds their answers kept.
func randWord(n int) string { return fetch.ProbeName("dirs " + strconv.Itoa(n)) }

// Notes says what the sweeps' summaries show of calibration: answers held
// back for being the page that names which cannot exist get, and the
// directories where calibration could filter nothing, so their wildcard
// answers are among the paths listed (the second result is true then).
func Notes(obs []types.StoredObservation) ([]string, bool) {
	held := 0
	var loose []string
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "dirs" {
			continue
		}
		var p struct {
			Held       int      `json:"held"`
			Unfiltered []string `json:"unfiltered"`
		}
		if json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		held += p.Held
		for _, d := range p.Unfiltered {
			if !slices.Contains(loose, d) {
				loose = append(loose, d)
			}
		}
	}
	var out []string
	if held > 0 {
		out = append(out, fmt.Sprintf("%d paths answered with the page that names that cannot exist get (the same status, title and words, though no size, word count or line count is shared) and were held back, not listed (-ac=false lists them)", held))
	}
	if len(loose) > 0 {
		out = append(out, fmt.Sprintf("calibration could filter nothing in %s: the answers to names that cannot exist share no size, word count, line count, title or words, so the wildcard answers are among the paths listed", strings.Join(loose[:min(len(loose), 3)], ", ")+map[bool]string{true: " and others", false: ""}[len(loose) > 3]))
	}
	return out, len(loose) > 0
}
