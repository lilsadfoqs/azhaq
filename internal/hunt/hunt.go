// Package hunt ranks a mapped surface: which routes, hosts and files a
// tester should open first, and why. One row per route template; every
// row names the evidence behind its score and the command to run next.
package hunt

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// Input is what a ranking reads, all from the workspace and the roles
// output; the command fills it.
type Input struct {
	DB        string // the workspace path, for the commands in Next
	Rows      []engine.MapEntry
	Obs       []types.StoredObservation
	Secrets   []Secret
	Takeovers []Takeover
	Roles     []RoleRow
	Listeners []Listener // what the run named on each listener, one record each
	Measured  []Measured // findings measured of a name, apart from its routes and leads
	Now       time.Time
	Since     time.Duration // "new" means first seen within this long
}

// Secret is a credential a script carried; Where is the file. Name, Preview
// (the value, redacted), Rule and Entropy are the evidence a reader judges it by.
// Known says the value's own format names it (a key with a known shape), not a
// guess from the name it was assigned to.
type Secret struct {
	Kind, Severity, Where string
	Name, Preview, Rule   string
	Entropy               float64
	Known                 bool
}

// Takeover is a name another party may claim.
type Takeover struct {
	Host   string
	Strong bool
	// Dangling: the claim rests on a CNAME target that does not resolve and
	// nothing else.
	Dangling bool
	Detail   string
}

// Reason is one piece of evidence for a row's rank.
type Reason struct {
	Signal string `json:"signal"`
	Detail string `json:"detail"`
}

// Row is one line of the hunt list.
type Row struct {
	Rank    int      `json:"rank"`
	Score   int      `json:"score"`
	Key     string   `json:"key"`
	Type    string   `json:"type"`
	Reasons []Reason `json:"reasons"`
	Next    string   `json:"next"`
	// Tier is finding for a row with a proven signal (the answer, the secret's
	// own format, the service's own page shows it), identification for a listener
	// the run named (a product, and a version or none), and lead for the rest. Check,
	// on a lead, is the check that would prove it; Proof, on a finding of a path
	// check, is the request, the excerpt of the answer and the command that
	// shows it again.
	Tier  string       `json:"tier"`
	Check string       `json:"check,omitempty"`
	Proof *proof.Proof `json:"proof,omitempty"`
	// Template is set on the row of an input the pages of an origin carry in
	// common: the input, and on how many of the origin's pages.
	Template *Template `json:"template,omitempty"`
	// Ident is set on the row of a listener the run named (Type Service): its
	// fields (kind, host, port, product, version, advisory_id, label…) are the
	// row's own in JSON.
	*Ident

	scope   string
	signals int  // distinct signals, "new" not counted
	named   bool // nothing but a script's naming or a DNS answer: no server confirmed it
}

// Template says a row is an origin's template input: on Pages of its Of
// fetched pages.
type Template struct {
	Input string `json:"input"`
	Pages int    `json:"pages"`
	Of    int    `json:"of"`
}

// cand is a route template while its signals are collected.
type cand struct {
	key, typ, scope string
	instances       []string // the keys of the map rows folded into it
	weights         map[string]int
	reasons         []Reason
	roleURL, roleM  string // the roles row behind a cross-role reason
	roleDir         string // and the -dir of the roles run that listed it
	origin          string
	fresh           bool
	named           int  // instances only a script names, whose GET answered 404 or 410
	dangling        bool // a takeover that rests on NXDOMAIN alone
	namedGET        int  // that status
	tmpl            *Template
	proved          map[string]bool // the signals an answer or a format proves
	check           string          // the check a path verdict names, for a lead
	proof           *proof.Proof
}

type hunter struct {
	in        Input
	cands     map[string]*cand
	apiDoc    map[string]bool // entity IDs of API descriptions the run parsed
	errs      map[string]errText
	verdicts  map[string]proof.Verdict // path checks: what the answer to each URL amounts to
	reflected map[string]bool          // route keys with a parameter whose value came back
	chrome    map[string]*chromeInfo   // origin and input name carried by most of the origin's pages
	cut       time.Time
	old       bool                         // some URL is older than the window: "new" tells rows apart
	maps      map[string][]engine.MapEntry // source map rows by origin: one row per host (sourceMaps)
}

// errText is what a failed answer's body showed: its kind (webextract's
// ErrSQL, ErrDebug, ErrStack) and the text that says so.
type errText struct{ kind, sample string }

// Build ranks the surface: best first, rows with no signal of their own
// left out.
func Build(in Input) []Row {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	h := &hunter{in: in, cands: map[string]*cand{}, apiDoc: apiDescriptions(in.Obs), cut: in.Now.Add(-in.Since)}
	h.errs, h.reflected = answersOf(in.Obs)
	h.verdicts = proof.Judge(proof.AnswersOf(in.Obs))
	h.chrome = chromeInputs(in.Rows)
	for _, r := range in.Rows {
		if r.Entity.Type == types.TypeURL && r.Entity.FirstSeen.Before(h.cut) {
			h.old = true
		}
	}
	for _, r := range in.Rows {
		switch r.Entity.Type {
		case types.TypeURL:
			h.url(r)
		case types.TypeHostname:
			h.host(r)
		}
	}
	h.sourceMaps()
	h.templates()
	h.secrets()
	h.takeovers()
	h.roles()
	var out []Row
	for _, l := range in.Listeners {
		out = append(out, l.row(in.DB))
	}
	for _, m := range in.Measured {
		out = append(out, m.row(in.DB))
	}
	for _, c := range h.cands {
		if c.fresh && h.old {
			c.add("new", "first seen within "+in.Since.String())
		}
		if len(c.weights) == 0 || (len(c.weights) == 1 && c.weights["new"] > 0) {
			continue // a row whose only signal is "new" never ranks
		}
		out = append(out, c.row(in.DB))
	}
	sortRows(out)
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// sortRows orders best first: findings, then identifications (a version seen
// before none seen), then leads; in each, rows the server
// confirmed before routes only a script names and names that rest on NXDOMAIN
// alone, then by score, then target scope before fan-out, then more distinct
// signals, then key.
func sortRows(out []Row) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.tierRank() != b.tierRank():
			return a.tierRank() < b.tierRank()
		case a.named != b.named:
			return !a.named
		case a.Score != b.Score:
			return a.Score > b.Score
		case (a.scope == "target") != (b.scope == "target"):
			return a.scope == "target"
		case a.signals != b.signals:
			return a.signals > b.signals
		}
		return a.Key < b.Key
	})
}

// add records one reason; a signal counts once toward the score, at the
// highest weight any of its reasons had.
func (c *cand) addW(signal string, w int, detail string) {
	if w <= 0 {
		return
	}
	// One reason per signal, the strongest; the roles verdicts keep all.
	for i, r := range c.reasons {
		if r.Signal != signal || signal == "cross-role" {
			if r.Signal == signal && r.Detail == detail {
				return
			}
			continue
		}
		if w > c.weights[signal] {
			c.reasons[i].Detail, c.weights[signal] = detail, w
		}
		return
	}
	c.reasons = append(c.reasons, Reason{signal, detail})
	if w > c.weights[signal] {
		c.weights[signal] = w
	}
}

func (c *cand) add(signal, detail string) { c.addW(signal, weights[signal], detail) }

// addProved is addW for a signal whose own evidence proves it: the row is a
// finding.
func (c *cand) addProved(signal string, w int, detail string) {
	if w <= 0 {
		return
	}
	c.addW(signal, w, detail)
	if c.proved == nil {
		c.proved = map[string]bool{}
	}
	c.proved[signal] = true
}

func (c *cand) row(db string) Row {
	rs := append([]Reason(nil), c.reasons...)
	named := c.named > 0 && c.named == len(c.instances)
	if c.dangling && len(c.weights) == 1 {
		named = true
	}
	if named && !c.dangling {
		rs = append(rs, Reason{"unconfirmed", fmt.Sprintf("named by a script, not confirmed: GET %d", c.namedGET)})
	}
	sort.SliceStable(rs, func(i, j int) bool { return c.weights[rs[i].Signal] > c.weights[rs[j].Signal] })
	score, n := 0, 0
	for s, w := range c.weights {
		score += w
		if s != "new" {
			n++
		}
	}
	best := ""
	if len(rs) > 0 {
		best = rs[0].Signal
	}
	row := Row{Score: score, Key: c.display(), Type: c.typ, Reasons: rs, Next: c.next(db, best), Template: c.tmpl, scope: c.scope, signals: n, named: named}
	if len(c.proved) > 0 {
		row.Tier, row.Proof = proof.TierFinding, c.proof
		return row
	}
	row.Tier = proof.TierLead
	if best == "exposed-file" || best == "exposed-panel" {
		row.Check = c.check
	}
	if row.Check == "" {
		row.Check = leadChecks[best]
	}
	if row.Check == "" {
		row.Check = "request it and read whether the answer shows what its name says"
	}
	return row
}

// display is the key a row shows: the URL itself when only one was seen,
// else the template that folds them.
func (c *cand) display() string {
	if len(c.instances) == 1 {
		return c.instances[0]
	}
	return c.key
}

// get finds or makes the candidate of a type and key.
func (h *hunter) get(typ, key, scope string) *cand {
	id := typ + "\x00" + key
	c := h.cands[id]
	if c == nil {
		c = &cand{key: key, typ: typ, scope: scope, weights: map[string]int{}}
		h.cands[id] = c
	}
	if scope == "target" {
		c.scope = scope
	}
	return c
}

func apiDescriptions(obs []types.StoredObservation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		if o.Collector == "azhaq-openapi" && o.Kind == "api" {
			out[o.EntityID] = true
		}
	}
	return out
}

// answersOf reads what the observations say of failed answers and of
// parameters found by a search: the error text of a 5xx body, per entity,
// and the routes with a parameter whose value came back.
func answersOf(obs []types.StoredObservation) (map[string]errText, map[string]bool) {
	errs, reflected := map[string]errText{}, map[string]bool{}
	for _, o := range obs {
		switch o.Collector {
		case "azhaq-http":
			var p struct {
				Kind   string `json:"error_text"`
				Sample string `json:"error_sample"`
			}
			if json.Unmarshal(o.Payload, &p) == nil && p.Kind != "" {
				errs[o.EntityID] = errText{p.Kind, p.Sample}
			}
		case "azhaq-params":
			var p struct {
				URL string            `json:"url"`
				Why map[string]string `json:"why"`
			}
			if json.Unmarshal(o.Payload, &p) != nil {
				continue
			}
			for _, why := range p.Why {
				if strings.Contains(why, "reflected") {
					reflected[webextract.RouteKey(p.URL)] = true
				}
			}
		}
	}
	return errs, reflected
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func join(xs []string, n int) string {
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + ", …"
	}
	return strings.Join(xs, ", ")
}
