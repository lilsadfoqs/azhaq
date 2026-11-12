package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
)

// Canaries: the replay asks one role at a time, and a session can die
// while it does (a token that lives minutes, a server that logs a session
// out). Each signed-in role's session is checked on an endpoint only a
// live session reads (its own "/me", a page the anonymous role is
// refused, or -canary) before its replay, every -canary-every requests,
// and after it. A check that fails renews the session once (the role's
// -role-cmd again, or a new sign-in with Chrome for -role-login) and asks
// again what was asked since the last good check; what was asked between
// a good check and one that still fails is marked session_suspect.

// canary is how one role's session is checked.
type canary struct {
	url  string
	re   *regexp.Regexp // what a live session's body holds, given with -canary
	want answer         // a live session's answer, from the role's run
}

// canarySpec is one -canary [ROLE:]URL[=REGEX].
type canarySpec struct {
	role, url string
	re        *regexp.Regexp
}

// parseCanaries reads -canary [ROLE:]URL[=REGEX]: without ROLE, for every
// signed-in role not given one of its own. The regex follows the first =
// after the path; a query's own key=value pairs stay in the URL.
func parseCanaries(specs []string, roles []role) ([]canarySpec, error) {
	var out []canarySpec
	for _, s := range specs {
		c := canarySpec{}
		rest := s
		if who, after, ok := strings.Cut(s, ":"); ok && !strings.HasPrefix(after, "//") {
			if !slices.ContainsFunc(roles, func(r role) bool { return r.name == who && !r.anonymous() }) {
				return nil, usagef("-canary %q: no signed-in role is named %s", s, who)
			}
			c.role, rest = who, after
		}
		u, re := rest, ""
		if q := strings.Index(rest, "?"); q < 0 {
			u, re, _ = strings.Cut(rest, "=")
		} else {
			last := q + 1 + strings.LastIndex(rest[q+1:], "&") + 1
			if i := strings.Index(rest[last:], "="); i >= 0 {
				if j := strings.Index(rest[last+i+1:], "="); j >= 0 {
					cut := last + i + 1 + j
					u, re = rest[:cut], rest[cut+1:]
				}
			}
		}
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return nil, usagef("-canary %q: want [ROLE:]URL[=REGEX], an http(s) URL", s)
		}
		c.url = u
		if re != "" {
			if c.re, err = regexp.Compile(re); err != nil {
				return nil, usagef("-canary %q: %v", s, err)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// pickCanaries chooses each signed-in role's canary: the -canary given for
// it, or for every role; else, of what its run read, its own "/me"-like
// answer, then one of its own objects (made), then an endpoint the
// anonymous role was refused; never one the anonymous role reads alike.
// JSON first, then the shortest.
func pickCanaries(roles []role, answers map[string]map[string]answer, made map[string]instance, specs []canarySpec, own map[string]bool) map[string]*canary {
	anon := ""
	for _, r := range roles {
		if r.anonymous() {
			anon = r.name
			break
		}
	}
	out := map[string]*canary{}
	for _, r := range roles {
		if r.anonymous() {
			continue
		}
		var given *canarySpec
		for i := range specs {
			if specs[i].role == r.name || specs[i].role == "" && given == nil {
				given = &specs[i]
			}
		}
		if given != nil {
			out[r.name] = &canary{url: given.url, re: given.re, want: answers[r.name][given.url]}
			continue
		}
		best, rank := "", 99
		for u, a := range answers[r.name] {
			if !reads(a) || !replayable(u, own) {
				continue
			}
			b, ok := answers[anon][u]
			if ok && reads(b) && b.Hash == a.Hash {
				continue // the session tells nothing here
			}
			k := 0
			switch {
			case meLike(u):
			case made[u].owner == r.name:
				k = 2
			case ok && refused(b):
				k = 4
			default:
				continue
			}
			if len(a.Keys) == 0 {
				if a.Title == "" {
					continue // nothing to tell a live answer by but its bytes
				}
				k++
			}
			if k < rank || k == rank && (len(u) < len(best) || len(u) == len(best) && u < best) {
				best, rank = u, k
			}
		}
		if best != "" {
			out[r.name] = &canary{url: best, want: answers[r.name][best]}
		}
	}
	return out
}

// signInCanaries finds a check for each signed-in role that has none, from
// its Chrome sign-in: each GET the browser sent after submitting the form,
// with the session, is a candidate. A candidate is read once with the
// session (unless the role's run already did) and once without it, as the
// anonymous role is asked, a control. It is chosen when the session tells
// the two apart by the rules pickCanaries uses: the answers differ, and
// the URL is a "/me" or the control was refused. The candidates are asked in
// the order of those rules, a "/me" first then the shortest, and the first
// to qualify is the role's check. It returns the requests sent, a note per
// role given a check naming it and what the control answered, and for each
// role whose candidates were tried and none qualified, how many were.
func signInCanaries(roles []role, picked map[string]*canary, signed map[string]browser.Session, loginURL string, answers map[string]map[string]answer, own map[string]bool, rate float64, budget int, refusal *regexp.Regexp) (sent int, notes []string, tried map[string]int, err error) {
	tried = map[string]int{}
	ctx, stop := stopContext()
	defer stop()
	fetch.Reset()
	defer fetch.Reset()
	egress.SetRate(rate)
	rolesEgress()
	egress.SetScope(func(h string) bool { return own[normalize.Hostname(h)] })
	holdDeny()
	anon := http.Header{}
	for _, r := range roles {
		if r.anonymous() {
			if r.session != nil {
				anon = r.session.Clone()
			}
			break
		}
	}
	ask := func(h http.Header, u string) (answer, error) {
		if sent >= budget {
			return answer{}, fmt.Errorf("%w: some sign-in pages were not asked to find a session check", errReplayMax)
		}
		sent++
		a, body, err := askFresh(ctx, h, u, own)
		if err == nil && ok2xx(a.Status) && refusal != nil && refusal.Match(body) {
			a.Refusal = true
		}
		return a, err
	}
	for _, r := range roles {
		if r.anonymous() || picked[r.name] != nil {
			continue
		}
		var cands []string
		for _, u := range signed[r.name].Gets {
			if u != loginURL && replayable(u, own) && !slices.Contains(cands, u) {
				cands = append(cands, u)
			}
		}
		slices.SortFunc(cands, func(a, b string) int {
			if c := cmp.Compare(boolInt(!meLike(a)), boolInt(!meLike(b))); c != 0 {
				return c
			}
			return cmp.Or(cmp.Compare(len(a), len(b)), cmp.Compare(a, b))
		})
		for _, u := range cands {
			a, have := answers[r.name][u]
			if !have {
				if a, err = ask(r.session, u); err != nil {
					if errors.Is(err, errReplayMax) || errors.Is(err, neterr.ErrBudget) {
						return sent, notes, tried, err
					}
					continue
				}
			}
			if !reads(a) || len(a.Keys) == 0 && a.Title == "" {
				continue // not read with the session, or nothing to tell a live answer by but its bytes
			}
			b, err := ask(anon, u)
			if err != nil {
				if errors.Is(err, errReplayMax) || errors.Is(err, neterr.ErrBudget) {
					return sent, notes, tried, err
				}
				tried[r.name]++
				continue
			}
			tried[r.name]++
			if reads(b) && b.Hash == a.Hash {
				continue // the session tells nothing here
			}
			if !meLike(u) && reads(b) {
				continue // a different body is not enough to know a dead session from a changed page
			}
			picked[r.name] = &canary{url: u, want: a}
			notes = append(notes, fmt.Sprintf("role %s: its session is checked on %s, a page the browser asked for after signing in; asked without the session it answered %s", r.name, pathOf(u), answerCell(b)))
			delete(tried, r.name)
			break
		}
	}
	return sent, notes, tried, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// alive asks the canary with the session h: a live session reads it, and
// its body holds the -canary regex, or it is the answer the role's run
// got (the same body, the same JSON fields, or the same page title).
func (c *canary) alive(ctx context.Context, h http.Header, own map[string]bool, refusal *regexp.Regexp) (bool, answer) {
	a, body, err := askFresh(ctx, h, c.url, own)
	if err != nil || !reads(a) || refusal != nil && refusal.Match(body) {
		return false, a
	}
	if c.re != nil {
		return c.re.Match(body), a
	}
	w := c.want
	switch {
	case w.Status == 0:
		c.want = a // a -canary without a regex: the first live answer is the one to keep
		return true, a
	case a.Hash == w.Hash:
		return true, a
	case len(w.Keys) > 0:
		return len(a.Keys) > 0 && !fieldsDiffer(a, w), a
	}
	return w.Title != "" && a.Title == w.Title, a
}

// replayWatch is how replayAll watches the sessions.
type replayWatch struct {
	every       int // requests between checks; 0: no checks
	canaries    map[string]*canary
	renew       func(i int) error // a new session for roles[i]
	refusal     *regexp.Regexp
	notes       []string
	failed      bool            // a request got no answer, or answers are suspect: the comparison misleads
	pausedRoles map[string]bool // roles paused on session loss: their remaining work is not attempted
}

// renewer renews a role's session: its -role-cmd run again, or a new
// sign-in on loginURL with Chrome, as its run signed in. A role given with
// -role headers cannot be renewed. left, when not nil, is what the command's
// budget has left: the sign-in is held to it.
func renewer(roles []role, loginURL string, quiet bool, left func() int64) func(int) error {
	return func(i int) error {
		r := roles[i]
		if r.session != nil {
			roles[i].past = append(roles[i].past, r.session.Clone()) // its values are still taken out of what is kept
		}
		switch {
		case r.cmd != "":
			lines, err := cmdHeaders(r)
			if err != nil {
				return err
			}
			if roles[i].session == nil {
				roles[i].session = http.Header{}
			}
			for k, v := range headerOf(lines) {
				roles[i].session[k] = v
			}
			return nil
		case r.user != "":
			base := roles[i].session.Clone()
			if base == nil {
				base = http.Header{}
			}
			base.Del("Cookie")
			base.Del("Authorization")
			fetch.Reset()
			rolesEgress()
			holdDeny()
			if left != nil {
				if left() == 0 {
					return fmt.Errorf("the sign-in was not made: %w", neterr.ErrBudget)
				}
				egress.SetMaxRequests(left())
			}
			fetch.Extra = base
			_, err := quietly(quiet, func() (*report, error) {
				_, err := signIn(nil, loginURL, r.user, r.pass, newReport("roles"), nil)
				return nil, err
			})
			s := fetch.Extra.Clone()
			fetch.Reset()
			if err != nil {
				return err
			}
			roles[i].session = s
			return nil
		}
		return errors.New("its session was given with -role or -har, with no -role-cmd or -role-login, and roles cannot renew it")
	}
}

// maxRenewals caps the new sessions one role's replay asks for: a token
// that lives a minute dies more than once in a long replay.
const maxRenewals = 5

// roleReplay asks one role the URLs it has no answer for, through its
// session, checking the session as it goes; sent counts every request,
// checks and retries too, against budget.
type roleReplay struct {
	ctx     context.Context
	roles   []role
	i       int
	answers map[string]map[string]answer
	own     map[string]bool
	rate    float64
	w       *replayWatch
	sent    *int
	budget  int

	since    []string // asked since the last good check
	good     bool     // the last check found the session alive
	renewals int      // renewals tried
	renewed  int      // new sessions that passed their check
	noRenew  string   // why the last renewal did not give a working session
	paused   bool     // the session did not come back: the rest was not attempted
	notTried int      // URLs not attempted because the session was paused
	total    int      // URLs this role was to be asked
	spent    bool     // a new session failed too, or none could be had: no more are asked for
	retried  int
	suspect  int
	failedAt string      // the first failed check: its URL and status
	unasked  int         // URLs left when the budget ran out
	failed   askFailures // URLs whose request got no answer, and why
}

func (rr *roleReplay) setup() {
	fetch.Reset()
	egress.SetRate(rr.rate)
	rolesEgress()
	own := rr.own
	egress.SetScope(func(h string) bool { return own[normalize.Hostname(h)] })
	holdDeny()
	fetch.Extra = rr.roles[rr.i].session.Clone()
}

func (rr *roleReplay) ask(u string) {
	res, _, err := fetch.Do(rr.ctx, fetch.Client(nil), u)
	*rr.sent += max(1, len(res.Hops)) // each redirect hop is a request too
	if err != nil {
		if rr.failed == nil {
			rr.failed = askFailures{}
		}
		rr.failed.add(u, err)
		return
	}
	delete(rr.failed, u)
	rr.answers[rr.roles[rr.i].name][u], _ = resultAnswer(res)
}

// check asks the role's canary; with no budget left it is not asked, and
// the session is taken as it was.
func (rr *roleReplay) check() bool {
	c := rr.w.canaries[rr.roles[rr.i].name]
	if *rr.sent >= rr.budget {
		return rr.good
	}
	*rr.sent++
	ok, a := c.alive(rr.ctx, rr.roles[rr.i].session, rr.own, rr.w.refusal)
	if !ok && rr.failedAt == "" {
		rr.failedAt = fmt.Sprintf("%s → %d", pathOf(c.url), a.Status)
		if a.Status == 0 {
			rr.failedAt = pathOf(c.url) + " → no answer"
		}
	}
	return ok
}

// renew gets the role a new session and checks it. A session that fails
// its check as soon as it is had is the last asked for.
func (rr *roleReplay) renew() bool {
	if rr.spent || rr.w.renew == nil || rr.renewals >= maxRenewals || *rr.sent >= rr.budget {
		return false
	}
	rr.renewals++
	if err := rr.w.renew(rr.i); err != nil {
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s: its session could not be renewed during the replay: %v", rr.roles[rr.i].name, err))
		rr.noRenew = "its renewal failed"
		if r := rr.roles[rr.i]; r.cmd == "" && r.user == "" {
			rr.noRenew = "it has no -role-cmd or -role-login to renew it"
		}
		rr.spent = true
		rr.setup()
		return false
	}
	rr.setup() // the new session, and an empty cache: what is asked again is sent again
	ok := rr.check()
	rr.spent = !ok
	if ok {
		rr.renewed++
	} else {
		rr.noRenew = "the new session failed its check too"
	}
	return ok
}

// checkpoint checks the session after a stretch of requests: the stretch
// stands when the checks before and after it found the session alive.
// Else the session is renewed and the stretch asked again; what still has
// no live session around it is suspect.
func (rr *roleReplay) checkpoint() {
	ok := rr.check()
	if ok && rr.good {
		rr.since = nil
		return
	}
	var left []string // not asked again: as suspect as they were
	if !ok && rr.renew() {
		redo := rr.since
		rr.since = nil
		for _, u := range redo {
			if *rr.sent >= rr.budget || rr.ctx.Err() != nil {
				left = append(left, u)
				continue
			}
			rr.ask(u)
			rr.retried++
			rr.since = append(rr.since, u)
		}
		if ok = rr.check(); ok {
			rr.since = left
			rr.good = true
		}
	}
	name := rr.roles[rr.i].name
	for _, u := range append(left, rr.since...) {
		if a, ok := rr.answers[name][u]; ok && !a.SessionSuspect {
			a.SessionSuspect = true
			rr.answers[name][u] = a
			rr.suspect++
		}
	}
	rr.since, rr.good = nil, ok
	if !ok {
		// Pause this role: asking the rest with a dead session would
		// spend the budget on near-anonymous answers. They stay
		// not-attempted (status 0) until a renewed session is given.
		rr.paused = true
		if rr.w.pausedRoles == nil {
			rr.w.pausedRoles = map[string]bool{}
		}
		rr.w.pausedRoles[rr.roles[rr.i].name] = true
	}
}

// run asks todo, checking the session before, every w.every requests, and
// after.
func (rr *roleReplay) run(todo []string) error {
	rr.total = len(todo)
	rr.setup()
	c := rr.w.canaries[rr.roles[rr.i].name]
	watch := c != nil && rr.w.every > 0
	rr.good = true
	if watch {
		if rr.good = rr.check(); !rr.good {
			rr.good = rr.renew()
		}
		if !rr.good {
			rr.paused, rr.notTried = true, len(todo)
			if rr.w.pausedRoles == nil {
				rr.w.pausedRoles = map[string]bool{}
			}
			rr.w.pausedRoles[rr.roles[rr.i].name] = true
			rr.note()
			return nil
		}
	}
	n := 0
	for _, u := range todo {
		if err := rr.ctx.Err(); err != nil {
			return err
		}
		if *rr.sent >= rr.budget {
			rr.unasked = len(todo) - n
			break
		}
		rr.ask(u)
		rr.since = append(rr.since, u)
		if n++; watch && n%rr.w.every == 0 && n < len(todo) {
			rr.checkpoint()
			if rr.paused {
				rr.notTried = len(todo) - n
				break
			}
		}
	}
	if watch {
		rr.checkpoint()
	}
	rr.note()
	return nil
}

func (rr *roleReplay) note() {
	name := rr.roles[rr.i].name
	if n := len(rr.failed); n > 0 {
		rr.w.failed = true
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s: %s of the replay got no answer, so it is missing from the comparison: %s", name, plural(n, "request"), rr.failed.reasons()))
	}
	how := "its -role-cmd gave a new one"
	if rr.roles[rr.i].user != "" {
		how = "it signed in again"
	}
	if rr.renewed > 1 {
		how += fmt.Sprintf(" (%d times)", rr.renewed)
	}
	if rr.paused && rr.notTried > 0 {
		rr.w.failed = true
		proved := max(rr.total-rr.notTried-rr.suspect, 0)
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s: its remaining replay was paused on session loss: %s not attempted for it (not-attempted, status 0), so those rows are unproven for %s; they are neither proved nor suspect; give a renewed session (a -role-cmd that prints a fresh one, a -role-login sign-in, or new -role headers on a rerun) and run roles again to prove them; for %s the summary separates %s proved, %s suspect and %s not-attempted",
			name, plural(rr.notTried, "URL"), name, name, plural(proved, "answer"), plural(rr.suspect, "answer"), plural(rr.notTried, "answer")))
	}
	switch {
	case rr.suspect > 0:
		rr.w.failed = true
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s's session failed its check (%s) during the replay and did not come back: %s asked after it was last seen alive (session_suspect)",
			name, rr.failedAt, plural(rr.suspect, "answer")))
	case rr.renewed > 0 && rr.failedAt != "" && rr.retried == 0:
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s's session failed its check (%s) during the replay; %s", name, rr.failedAt, how))
	case rr.renewed > 0 && rr.failedAt != "":
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s's session failed its check (%s) during the replay; %s, and the %s asked since the last good check were asked again",
			name, rr.failedAt, how, plural(rr.retried, "request")))
	case rr.failedAt != "":
		rr.w.notes = append(rr.w.notes, fmt.Sprintf("role %s's session failed its check (%s) during the replay and was not renewed: %s", name, rr.failedAt, cmp.Or(rr.noRenew, "no renewal was tried")))
	}
}
