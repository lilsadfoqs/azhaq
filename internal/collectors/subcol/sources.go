package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtname"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitalyama"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/domainsproject"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/driftnet"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/gitlab"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hudsonrock"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/merklemap"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/onyphe"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/profundis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/pugrecon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconcloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconeer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/redhuntlabs"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/riddler"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rsecloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/scanmalware"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodanct"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/subdomaincenter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/submd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/thc"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatminer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/urlscan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/windvane"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
)

// keyNeed says whether a source works without an API key.
type keyNeed int

const (
	noKey keyNeed = iota
	optionalKey
	requiredKey
)

// source is one passive subdomain source.
type source struct {
	name    string
	need    keyNeed
	deflt   bool    // part of the default set
	perSec  float64 // request rate; 0 is unlimited
	verify  bool    // a name only it gave is kept when it resolves
	sampler bool    // asked again by sampled(): it keeps its own time
	recurse bool    // handles subdomains of a subdomain (-recursive)
	extra   bool    // not in subfinder's default set: bounded by -extra-wait
	collect func(ctx context.Context, domain string, keys []string, s *subscraping.Session) ([]string, error)
}

// pd adapts a subfinder source. A new instance is made per call because
// the instances keep keys and statistics.
func pd(newSource func() subscraping.Source, perSec float64) source {
	s := newSource()
	need := noKey
	switch s.KeyRequirement() {
	case subscraping.OptionalKey:
		need = optionalKey
	case subscraping.RequiredKey:
		need = requiredKey
	}
	return source{
		name:    s.Name(),
		need:    need,
		deflt:   s.IsDefault(),
		perSec:  perSec,
		recurse: s.HasRecursiveSupport(),
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			src := newSource()
			if len(keys) > 0 {
				src.AddApiKeys(keys)
			}
			ctx = context.WithValue(ctx, subscraping.CtxSourceArg, src.Name())
			var names, errs []string
			for r := range src.Run(ctx, domain, sess) {
				switch r.Type {
				case subscraping.Subdomain:
					names = append(names, r.Value)
				case subscraping.Error:
					if r.Error != nil && len(errs) < 3 {
						errs = append(errs, withWords(ctx, r.Error.Error()))
					}
				}
			}
			why := answeredWithError(ctx)
			switch {
			case why != "" && len(names) == 0:
				// The server's words, not the decoder's complaint about them;
				// an error page has no names: not an honest zero.
				return nil, errors.New(why)
			case len(errs) > 0:
				return names, errors.New(strings.Join(errs, "; "))
			case why != "":
				addNote(ctx, why)
			}
			return names, nil
		},
	}
}

// Rates follow subfinder's defaults (requests per second).
const perMinute = 1.0 / 60

func allSources() []source {
	return []source{
		pd(func() subscraping.Source { return &alienvault.Source{} }, 0),
		pd(func() subscraping.Source { return &anubis.Source{} }, 0),
		pd(func() subscraping.Source { return &bevigil.Source{} }, 0),
		pd(func() subscraping.Source { return &bufferover.Source{} }, 0),
		pd(func() subscraping.Source { return &builtwith.Source{} }, 0),
		pd(func() subscraping.Source { return &c99.Source{} }, 0),
		pd(func() subscraping.Source { return &censys.Source{} }, 0),
		pd(func() subscraping.Source { return &chinaz.Source{} }, 0),
		on(pd(func() subscraping.Source { return &commoncrawl.Source{} }, 0)),
		pd(func() subscraping.Source { return &crtname.Source{} }, 0),
		pd(func() subscraping.Source { return &digitalyama.Source{} }, 0),
		off(pd(func() subscraping.Source { return &digitorus.Source{} }, 0)),
		pd(func() subscraping.Source { return &dnsdb.Source{} }, 0),
		pd(func() subscraping.Source { return &dnsdumpster.Source{} }, 0),
		pd(func() subscraping.Source { return &dnsrepo.Source{} }, 0),
		pd(func() subscraping.Source { return &domainsproject.Source{} }, 0),
		pd(func() subscraping.Source { return &driftnet.Source{} }, 0),
		pd(func() subscraping.Source { return &fofa.Source{} }, 0),
		pd(func() subscraping.Source { return &fullhunt.Source{} }, 60*perMinute),
		pd(func() subscraping.Source { return &github.Source{} }, 83*perMinute),
		pd(func() subscraping.Source { return &gitlab.Source{} }, 0),
		pd(func() subscraping.Source { return &hackertarget.Source{} }, 2),
		on(pd(func() subscraping.Source { return &hudsonrock.Source{} }, 5)),
		pd(func() subscraping.Source { return &intelx.Source{} }, 0),
		pd(func() subscraping.Source { return &leakix.Source{} }, 0),
		pd(func() subscraping.Source { return &merklemap.Source{} }, 0),
		pd(func() subscraping.Source { return &netlas.Source{} }, 1),
		pd(func() subscraping.Source { return &onyphe.Source{} }, 0),
		pd(func() subscraping.Source { return &profundis.Source{} }, 0),
		pd(func() subscraping.Source { return &pugrecon.Source{} }, 10),
		pd(func() subscraping.Source { return &quake.Source{} }, 0),
		on(pd(func() subscraping.Source { return &rapiddns.Source{} }, 0)),
		off(pd(func() subscraping.Source { return &reconcloud.Source{} }, 0)),
		keyed(pd(func() subscraping.Source { return &reconeer.Source{} }, 0)),
		pd(func() subscraping.Source { return &redhuntlabs.Source{} }, 0),
		off(pd(func() subscraping.Source { return &riddler.Source{} }, 0)),
		pd(func() subscraping.Source { return &robtex.Source{} }, 0),
		pd(func() subscraping.Source { return &rsecloud.Source{} }, 0),
		pd(func() subscraping.Source { return &scanmalware.Source{} }, 0),
		pd(func() subscraping.Source { return &securitytrails.Source{} }, 2),
		pd(func() subscraping.Source { return &shodan.Source{} }, 1),
		pd(func() subscraping.Source { return &shodanct.Source{} }, 0),
		on(pd(func() subscraping.Source { return &sitedossier.Source{} }, 8*perMinute)),
		sampled(verified(pd(func() subscraping.Source { return &subdomaincenter.Source{} }, 0))),
		off(pd(func() subscraping.Source { return &submd.Source{} }, 0)),
		on(pd(func() subscraping.Source { return &thc.Source{} }, 0)),
		pd(func() subscraping.Source { return &threatbook.Source{} }, 0),
		off(pd(func() subscraping.Source { return &threatcrowd.Source{} }, 0)),
		off(pd(func() subscraping.Source { return &threatminer.Source{} }, 0)),
		pd(func() subscraping.Source { return &urlscan.Source{} }, 1),
		pd(func() subscraping.Source { return &virustotal.Source{} }, 4*perMinute),
		on(pd(func() subscraping.Source { return &waybackarchive.Source{} }, 15*perMinute)),
		pd(func() subscraping.Source { return &whoisxmlapi.Source{} }, 50),
		pd(func() subscraping.Source { return &windvane.Source{} }, 0),
		pd(func() subscraping.Source { return &zoomeyeapi.Source{} }, 0),
		certspotterSource(),
		chaosSource(),
		crtshSource(),
		historySource(),
	}
}

// off takes a source out of the default set: it was dead or refused
// every request when last checked (2026-11-03: digitorus answered 403,
// threatminer 522, submd 523, and reconcloud, riddler and threatcrowd no
// longer resolve), and a run that always reports the same failures
// teaches its reader to ignore failures. -sources NAME or -all-sources
// still runs it.
func off(s source) source {
	s.deflt = false
	return s
}

// on puts a keyless source that answers into the default set, although
// subfinder leaves it out of its own: rapiddns, thc and hudsonrock
// answered for tesla.com with names the others lacked (2026-10-27), and
// commoncrawl, sitedossier and waybackarchive are slow, not dead: each is
// bounded by -source-timeout, so one of them cannot hold the run, and a
// failure of one is a failed source of the summary, not of the result.
func on(s source) source {
	s.deflt, s.extra = true, true
	return s
}

// verified marks a source that pads its answer with made-up names:
// subdomain.center answers about 500 names per call, nearly all random
// and different each time, with the odd real one among them (2026-10-27).
// A name only such a source gave is kept when it resolves (not to a
// wildcard).
func verified(s source) source {
	s.verify = true
	return s
}

// sampled asks a keyless source again while its answers keep adding names
// that resolve: subdomain.center answers a different random 500 per call
// (2026-10-29: five calls gave 2135 tesla.com names, 49 live hosts one call
// missed). Each round's new names are resolved (the checker in ctx) while
// the next round is asked; it stops when a round adds no new live name and
// the names seen are most of the pool the rounds' repeats estimate (a round
// that finds none says little while a name in twenty is still unseen), and the
// call made ahead is dropped.
// Without resolvers it stops when under a tenth of a round is new. The
// source's bound (-source-timeout) is for asking: a request may take that
// long and the asking half of it in all; resolving is paced by -dns-rate.
func sampled(s source) source {
	collect := s.collect
	s.sampler = true
	s.collect = func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
		if len(keys) > 0 {
			return collect(ctx, domain, keys, sess) // a key pages the whole set
		}
		timeout := sourceTimeoutOf(ctx)
		chk, _ := ctx.Value(checkerKey{}).(*checker)
		n, _ := ctx.Value(samplesKey{}).(int)
		ceiling := sampleCeiling(n)
		var budgetFrom time.Time // the budget for further samples starts when the first is checked
		var asking time.Duration
		var names []string
		var calls [][]string // each round's names, for the pool estimate
		seen := map[string]bool{}
		// ask makes one call; the next one is made while the names of the
		// last are looked up, so a round costs the longer of the two.
		type reply struct {
			got  []string
			err  error
			took time.Duration
		}
		ask := func() (<-chan reply, context.CancelFunc) {
			countCall(ctx)
			fctx, cancel := context.WithTimeout(ctx, timeout)
			ch := make(chan reply, 1)
			go func() {
				defer guard.Recover(ctx)
				t0 := time.Now()
				got, err := collect(fctx, domain, nil, sess)
				ch <- reply{got, err, time.Since(t0)}
			}()
			return ch, cancel
		}
		next, cancelNext := ask()
		for call := 0; call < ceiling; call++ {
			r := <-next
			cancelNext()
			got, err := r.got, r.err
			asking += r.took
			recordRound(ctx, got)
			calls = append(calls, got)
			var fresh []string
			for _, n := range got {
				if !seen[n] {
					seen[n] = true
					names = append(names, n)
					fresh = append(fresh, n)
				}
			}
			keepPartial(ctx, names)
			st := roundStat{Got: len(got), New: len(fresh)}
			switch {
			case err != nil && (len(names) == 0 || ctx.Err() != nil):
				return names, err
			case err != nil:
				return names, nil // later rounds were refused: the row says so
			case len(fresh) == 0:
				recordStop(ctx, stopSaturated)
				return names, nil
			case chk == nil && (n <= 1 || poolCovered(calls, len(seen))):
				// Nothing to check them against: a second sample would only
				// add more guesses, so one is taken, as subfinder takes it,
				// unless -guess-samples asks for more, until the names seen
				// are most of the pool.
				recordStop(ctx, stopUnchecked)
				return names, nil
			}
			var pending <-chan reply
			var cancelPending context.CancelFunc
			if call+1 < ceiling && ctx.Err() == nil {
				pending, cancelPending = ask()
			}
			t1 := time.Now()
			if chk != nil {
				before, _ := chk.totals()
				st.Live = chk.check(cleaned(fresh, domain))
				after, _ := chk.totals()
				st.Asked = after - before
			}
			took := time.Since(t1)
			st.Seconds = round(took.Seconds())
			recordStat(ctx, st)
			if call == 0 {
				budgetFrom = time.Now()
			}
			stop := false
			switch {
			case st.Live == 0 && poolCovered(calls, len(seen)):
				stop = true // nothing new resolves, and little is left unseen
				recordStop(ctx, stopNoLive)
			case n == 0 && time.Since(budgetFrom)+took > sampleBudget:
				// Another sample costs about what this one did: it is taken
				// only if it fits what is left of the budget.
				stop = true
				recordStop(ctx, stopBudget)
			case asking >= timeout/2, ctx.Err() != nil:
				stop = true
				recordStop(ctx, stopTime)
			}
			if !stop && pending == nil {
				recordStop(ctx, stopRounds)
			}
			if stop || pending == nil {
				if pending != nil {
					cancelPending() // the call made ahead is not needed
					<-pending
				}
				return names, nil
			}
			next, cancelNext = pending, cancelPending
		}
		return names, nil
	}
	return s
}

// Why a sampled source stopped asking, for its row ("sampling_stopped").
// The last is a bound, not a finding: more samples may hold more names.
const (
	stopSaturated = "a call gave no name it had not given"
	stopUnchecked = "the names are not looked up (no -live), so more samples would only add guesses (-guess-samples N takes up to N)"
	stopNoLive    = "the last sample had no new name that resolves, and the names seen are most of its estimated pool"
	stopTime      = "its time was used"
	stopBudget    = "another sample would not fit the 20 s budget for further samples"
	stopRounds    = "the most samples were taken"
)

// poolCoverage is the share of the pool a sampled source's rounds estimate
// that the names seen must reach before a round with no new live name ends
// the asking: one name in twenty may still be unseen.
const poolCoverage = 0.95

// poolCovered says whether the names seen are poolCoverage of the pool the
// rounds' repeats estimate. With no repeat yet there is no estimate: no.
func poolCovered(rounds [][]string, seen int) bool {
	est, ok := schnabel(rounds)
	return ok && float64(seen) >= poolCoverage*est
}

// boundedStop says whether a stop reason is a bound, not a finding.
func boundedStop(why string) bool { return why == stopTime || why == stopBudget || why == stopRounds }

// roundStat is one round of a sampled source, for its row: the names it
// gave, how many were new, how many of those were looked up and how many
// resolved and no other source had.
type roundStat struct {
	Got     int     `json:"names"`
	New     int     `json:"new"`
	Asked   int     `json:"looked_up"`
	Live    int     `json:"new_live"`
	Seconds float64 `json:"check_seconds"`
}

func recordStat(ctx context.Context, st roundStat) {
	if l, ok := ctx.Value(roundsKey{}).(*roundLog); ok {
		l.mu.Lock()
		l.stats = append(l.stats, st)
		l.mu.Unlock()
	}
}

// timeoutKey carries a run's -source-timeout to a source that keeps its own
// time: the session holds whole seconds, which lose a bound under one.
type timeoutKey struct{}

func sourceTimeoutOf(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(timeoutKey{}).(time.Duration); ok && d > 0 {
		return d
	}
	return DefaultSourceTimeout
}

type partialKey struct{}

// partialNames keeps what a sampled source has gathered, for Run to use
// when it stops waiting before the source returns.
type partialNames struct {
	mu    sync.Mutex
	names []string
}

func (p *partialNames) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.names...)
}

func keepPartial(ctx context.Context, names []string) {
	if p, ok := ctx.Value(partialKey{}).(*partialNames); ok {
		p.mu.Lock()
		p.names = append(p.names[:0], names...)
		p.mu.Unlock()
	}
}

type callsKey struct{}

// countCall adds one to the calls Run counts for the source (its row's
// "calls", shown by subs -v).
func countCall(ctx context.Context) {
	if n, ok := ctx.Value(callsKey{}).(*atomic.Int32); ok {
		n.Add(1)
	}
}

var (
	// sampleRounds is the most samples taken by default.
	sampleRounds = 12
	// sampleBudget bounds the further samples by default, from when the
	// first has been checked: the first is the reference's own work
	// (subfinder asks once, dnsx checks all of it) and is always checked.
	sampleBudget = 20 * time.Second
)

type samplesKey struct{}

// sampleCeiling is the most samples taken: -guess-samples, or by default
// sampleRounds.
func sampleCeiling(n int) int {
	if n > 0 {
		return n
	}
	return sampleRounds
}

// keyed marks a source that has started to require a key.
func keyed(s source) source {
	s.need = requiredKey
	return s
}

// crtshSource asks crt.sh as subfinder does: its public PostgreSQL first,
// limited to 10000 rows (which answers in seconds), and the JSON API when
// the database fails or has nothing. A page that came back full has more
// behind it: the rest is asked for without the limit, then from the JSON
// API, within the source's time, and the note says which gave the names.
func crtshSource() source {
	return source{
		name:    "crtsh",
		need:    noKey,
		deflt:   true,
		recurse: true,
		collect: func(ctx context.Context, domain string, _ []string, sess *subscraping.Session) ([]string, error) {
			page, rows, err := crtshDatabase(ctx, domain, sess.Client, crtshLimitedShare, crtshLimit)
			if err == nil && len(page) > 0 && rows < crtshLimit {
				return page, nil
			}
			if err == nil && len(page) > 0 {
				return crtshRest(ctx, domain, page, sess)
			}
			if err != nil {
				addNote(ctx, "crt.sh database: "+err.Error()+"; asked the JSON API")
			} else {
				addNote(ctx, "crt.sh database had no names; asked the JSON API")
			}
			names, jerr := crtshJSON(ctx, domain, sess)
			if jerr != nil && len(page) > 0 {
				return page, nil // the names the database gave before it failed
			}
			return append(page, names...), jerr
		},
	}
}

// crtshRest asks for what lies behind a full page: the database without
// the limit, then the JSON API. When neither answers the page is the
// answer, and the note says it may be short.
func crtshRest(ctx context.Context, domain string, page []string, sess *subscraping.Session) ([]string, error) {
	all, _, err := crtshDatabase(ctx, domain, sess.Client, crtshRestShare, 0)
	if err == nil && len(all) > 0 {
		addNote(ctx, fmt.Sprintf("crt.sh database: the first %d rows were a full page; asked again without the limit for the rest", crtshLimit))
		return append(page, all...), nil
	}
	if err == nil {
		err = errors.New("no names")
	}
	names, jerr := crtshJSON(ctx, domain, sess)
	if jerr == nil {
		addNote(ctx, fmt.Sprintf("crt.sh database: the first %d rows were a full page; the unlimited query failed (%v), the JSON API gave the rest", crtshLimit, err))
		return append(page, names...), nil
	}
	addNote(ctx, fmt.Sprintf("crt.sh database: the first %d rows were a full page and are all it gave: the rest failed (database: %v; JSON API: %v), so there may be more names", crtshLimit, err, jerr))
	return page, nil
}

// crtshJSON asks crt.sh's JSON endpoint, again a few times on a 5xx.
func crtshJSON(ctx context.Context, domain string, sess *subscraping.Session) ([]string, error) {
	u := "https://crt.sh/json?q=" + url.QueryEscape(domain)
	var rows []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	var err error
	for attempt, wait := 0, crtshRetryWait; attempt < crtshAttempts; attempt, wait = attempt+1, wait*2 {
		if err = getJSON(withOwnRetries(ctx), sess, "crtsh", u, nil, &rows); err == nil || !retry(err) {
			break
		}
		// crt.sh is often down for a while: a few retries, as many as the
		// source's own time (-source-timeout) leaves room for, but not
		// when this retry would be all the run waits for: subfinder asks once.
		if holdsRun(ctx) {
			addNote(ctx, "not asked again: every other source had answered and the run does not wait for a retry")
			break
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= wait {
			break
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(wait):
		}
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.CommonName)
		names = append(names, strings.Split(r.NameValue, "\n")...)
	}
	return names, nil
}

// crtshAttempts is how many times the JSON API is asked before its failure
// is the answer; crtshRetryWait is the first pause, doubled each time.
const crtshAttempts = 4

var crtshRetryWait = time.Second

// gatewayRE reads the status code of a failed answer in the two forms the
// requests give it: subfinder's "unexpected status code 502 received from
// URL", getJSON's "host 502" and "host answered 502: the server's words".
var gatewayRE = lazyre.New(`(?:status code|\s)(50[0234])(?::|\s+received from|$)`)

// retry: crt.sh's gateway errors and dropped connections pass (a 429 is
// waited out in the transport).
func retry(err error) bool {
	s := err.Error()
	return gatewayRE.MatchString(s) || strings.Contains(s, "EOF") || strings.Contains(s, "connection reset") || strings.Contains(s, "unexpected end of JSON")
}

// certspotterSource asks Cert Spotter. Unlike subfinder's version it also
// works without a key, at the free tier's rate, where it reads the first
// page only (100 issuances) and says so; with a key it pages with
// after=<last id> until a page is empty, as subfinder does.
func certspotterSource() source {
	return source{
		name:    "certspotter",
		need:    optionalKey,
		deflt:   true,
		recurse: true,
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			base := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) + "&include_subdomains=true&expand=dns_names"
			headers := map[string]string{}
			key := subscraping.PickRandom(keys, "certspotter")
			if key != "" {
				headers["Authorization"] = "Bearer " + key
			}
			var names []string
			after := ""
			for page := 0; page < certspotterMaxPages; page++ {
				u := base
				if after != "" {
					u += "&after=" + url.QueryEscape(after)
				}
				var rows []struct {
					ID       string   `json:"id"`
					DNSNames []string `json:"dns_names"`
				}
				if err := getJSON(ctx, sess, "certspotter", u, headers, &rows); err != nil {
					if len(names) > 0 {
						addNote(ctx, fmt.Sprintf("stopped after page %d: %v; the names of the pages before it are kept", page+1, err))
						return names, nil
					}
					return nil, err
				}
				for _, r := range rows {
					names = append(names, r.DNSNames...)
				}
				if len(rows) == 0 || rows[len(rows)-1].ID == "" {
					return names, nil
				}
				if key == "" {
					if len(rows) >= certspotterPage {
						addNote(ctx, "first page only (without a key it is not paged): more issuances exist; a Cert Spotter key in the provider file pages them all")
					}
					return names, nil
				}
				after = rows[len(rows)-1].ID
			}
			addNote(ctx, fmt.Sprintf("stopped at %d pages; more issuances exist", certspotterMaxPages))
			return names, nil
		},
	}
}

const (
	certspotterPage     = 100 // issuances per page
	certspotterMaxPages = 1000
)

type noteKey struct{}

// rowNote is what a source says about its own answer, for its row.
type rowNote struct {
	mu   sync.Mutex
	text string
}

func (n *rowNote) get() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.text
}

// addNote tells the run something about the source's answer: it is partial,
// and why. It is shown with the source's row and in the summary.
func addNote(ctx context.Context, text string) {
	if n, ok := ctx.Value(noteKey{}).(*rowNote); ok {
		n.mu.Lock()
		if n.text != "" {
			n.text += "; "
		}
		n.text += text
		n.mu.Unlock()
	}
}

// chaosSource asks ProjectDiscovery's Chaos dataset. It is written here
// because subfinder's version pulls in a large client library.
func chaosSource() source {
	return source{
		name:  "chaos",
		need:  requiredKey,
		deflt: true,
		collect: func(ctx context.Context, domain string, keys []string, sess *subscraping.Session) ([]string, error) {
			var body struct {
				Subdomains []string `json:"subdomains"`
			}
			u := "https://dns.projectdiscovery.io/dns/" + url.PathEscape(domain) + "/subdomains"
			if err := getJSON(ctx, sess, "chaos", u, map[string]string{"Authorization": subscraping.PickRandom(keys, "chaos")}, &body); err != nil {
				return nil, err
			}
			names := make([]string, 0, len(body.Subdomains))
			for _, s := range body.Subdomains {
				names = append(names, strings.TrimSuffix(s, ".")+"."+domain)
			}
			return names, nil
		},
	}
}

func getJSON(ctx context.Context, sess *subscraping.Session, name, u string, headers map[string]string, into any) error {
	ctx = context.WithValue(ctx, subscraping.CtxSourceArg, name)
	resp, err := sess.Get(ctx, u, "", headers)
	if err != nil {
		sess.DiscardHTTPResponse(resp)
		if w := withWords(ctx, err.Error()); w != err.Error() {
			return errors.New(w)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %d", resp.Request.URL.Host, resp.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(into)
	if err != nil {
		if why := answeredWithError(ctx); why != "" {
			return errors.New(why) // the server's words, not a decoder's
		}
	}
	return err
}

// SampleBudget and SampleRounds are the defaults -guess-samples goes beyond.
func SampleBudget() time.Duration { return sampleBudget }
func SampleRounds() int           { return sampleRounds }
