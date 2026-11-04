package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/types"
)

// stateChangeEntry is one GET request whose own name declares a state
// change, named before it is sent (in a plan, and in a run's first lines)
// and, for the ones a run finds on the way, in its summary with what became
// of it: held back and not sent (the default), or sent in this run.
type stateChangeEntry struct {
	Target      string `json:"target"`                // the seed target the request belongs to
	Method      string `json:"method"`                // always GET: the requests azhaq sends without a write flag
	URL         string `json:"url"`                   // the request that would be (or was) sent
	Word        string `json:"word"`                  // the word that declares the change: create, delete, reset, populate, logout, …
	Source      string `json:"source"`                // where the word is: its path, or its operationId or summary in an API description
	Description string `json:"description,omitempty"` // the operation's summary, when it gave the word
	DenyPath    string `json:"deny_path"`             // the -deny-path rule that would keep this request out
	// Status is what became of the request: stateGiven (a plan: a target you
	// gave), stateSent (the ledger holds a request for it), stateHeld (found on
	// the way and not sent) or stateNotAsked (found, and no request for it
	// was sent in this run).
	Status string `json:"status,omitempty"`
	// Send is the flag that sends a held back request.
	Send string `json:"send,omitempty"`
}

const (
	stateGiven    = "given as a target"
	stateSent     = "sent"
	stateHeld     = "held back"
	stateNotAsked = "not requested"
	stateUnknown  = "not recorded here"
)

// line is the entry as plan and a run's notes print it.
func (e stateChangeEntry) line() string {
	where := e.Source
	if e.Description != "" {
		where += fmt.Sprintf(" %q", e.Description)
	}
	var tail string
	switch e.Status {
	case stateHeld:
		tail = "held back, not sent: " + e.Send + " sends it"
	case stateSent:
		tail = "sent in this run (the ledger holds the request); keep it out of a later run with " + e.DenyPath
	case stateNotAsked:
		tail = "found, and no request for it was sent in this run"
	case stateUnknown:
		tail = "found; this process sent no request for it, and a worker may have (its ledger holds it)"
	default:
		tail = "it is a target you gave, so it is sent; keep it out with " + e.DenyPath
	}
	return fmt.Sprintf("%s %s may change state (the word %q in %s); %s", e.Method, e.URL, e.Word, where, tail)
}

// denyRuleFor is the -deny-path rule that excludes exactly this URL:
// an anchored regular expression on its path and query.
func denyRuleFor(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "-deny-path ^" + regexp.QuoteMeta(raw) + "$"
	}
	pq := u.Path
	if u.RawQuery != "" {
		pq += "?" + u.RawQuery
	}
	return "-deny-path ^" + regexp.QuoteMeta(pq) + "$"
}

// stateChangesOfSeeds are the entries among the targets given: a URL
// seed whose own path names a state change, in scope and not already
// kept out by a -deny-path rule (those are listed as skipped).
func stateChangesOfSeeds(seeds []types.Seed, rules scope.Rules) []stateChangeEntry {
	var out []stateChangeEntry
	seen := map[string]bool{}
	for _, s := range seeds {
		if s.Type != types.TypeURL {
			continue
		}
		u := s.Key()
		if seen[u] {
			continue
		}
		seen[u] = true
		if !rules.Empty() && !rules.AllowsSeed(s) {
			continue
		}
		if rules.DeniedPath(u) != "" {
			continue // kept out already: the plan lists it under skipped
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		word := statechange.OfPath(parsed.Path)
		if word == "" {
			continue
		}
		out = append(out, stateChangeEntry{Target: u, Method: "GET", URL: u, Word: word, Source: "its path", DenyPath: denyRuleFor(u), Status: stateGiven})
	}
	return out
}

// stateChangesOfOps are the entries in API descriptions a run has
// read: each GET operation whose path, operationId or summary declares a
// state change (never its description). It is a pure read of the
// observations, so a description produces its entries before any of its
// operations is requested.
func stateChangesOfOps(obs []types.StoredObservation) []stateChangeEntry {
	var out []stateChangeEntry
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-openapi" || o.Kind != "url" {
			continue
		}
		var p struct {
			URL  string `json:"url"`
			Path string `json:"path"`
			Ops  []struct {
				Method      string `json:"method"`
				Summary     string `json:"summary"`
				OperationID string `json:"operation_id"`
			} `json:"ops"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		for _, op := range p.Ops {
			if op.Method != "GET" {
				continue
			}
			path := p.Path
			if path == "" {
				if u, err := url.Parse(p.URL); err == nil {
					path = u.Path
				}
			}
			word, where := statechange.OfOperation(path, op.OperationID, op.Summary)
			if word == "" {
				continue
			}
			key := "GET " + p.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			e := stateChangeEntry{Target: p.URL, Method: "GET", URL: p.URL, Word: word, DenyPath: denyRuleFor(p.URL)}
			switch where {
			case "path":
				e.Source = "its path"
			case "operationId":
				e.Source = "its operationId " + op.OperationID + " in its API description"
			default:
				e.Source, e.Description = "its summary in its API description", op.Summary
			}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// stateChangesOfRows are the entries among the URLs a run found on
// the way (a link named /logout, a script's call): the ones no API
// description named, by their own path alone. A row the run did not ask
// for a reason that is no state change (a catch-all origin, a -deny-path
// rule) is not an entry.
func stateChangesOfRows(rows []mapRowLike) []stateChangeEntry {
	var out []stateChangeEntry
	seen := map[string]bool{}
	for _, r := range rows {
		if r.skipped && !r.held || seen[r.key] {
			continue
		}
		seen[r.key] = true
		word := statechange.OfURL(r.key)
		if word == "" {
			continue
		}
		out = append(out, stateChangeEntry{Target: r.key, Method: "GET", URL: r.key, Word: word, Source: "its path", DenyPath: denyRuleFor(r.key)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// mapRowLike is the part of a map row the state-change list reads.
type mapRowLike struct {
	key     string
	skipped bool
	held    bool // skipped because it was held back as state-changing
}

// mergeStateChanges joins entry lists, the first entry for a request
// winning, in URL order.
func mergeStateChanges(lists ...[]stateChangeEntry) []stateChangeEntry {
	seen := map[string]bool{}
	var out []stateChangeEntry
	for _, list := range lists {
		for _, e := range list {
			key := e.Method + " " + e.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return strings.Compare(out[i].Target, out[j].Target) < 0
	})
	return out
}

// heldWordOf is the word in a held-back reason (see neterr.HeldReason).
func heldWordOf(reason string) string {
	_, rest, ok := strings.Cut(reason, "(the word \"")
	if !ok {
		return ""
	}
	w, _, _ := strings.Cut(rest, "\"")
	return w
}

// normKey is the normalized form of a URL, for comparing the ones a list
// names with the ones a run sent.
func normKey(raw string) string {
	if n, err := normalize.URL(raw); err == nil {
		return n
	}
	return raw
}

// heldTargets are the URLs of skipped that were held back as
// state-changing, by normalized URL, with their word.
func heldTargets(skipped []engine.Skip) map[string]string {
	out := map[string]string{}
	for _, s := range skipped {
		if egress.IsHeldReason(s.Reason) {
			out[normKey(s.Target)] = heldWordOf(s.Reason)
		}
	}
	return out
}

// settleStateChanges is the run's final list of the GETs whose own name
// declares a state change, each with what became of it: sent only when this
// process recorded a request for it (the same moment the ledger line is
// made), held back when the run listed it as skipped for that, else not
// requested. found are the entries of the run's rows and API descriptions,
// pre the ones named before it started. A URL a -deny-path rule keeps out is
// not an entry: it is listed as skipped for the rule.
func settleStateChanges(rep *report, pre, found []stateChangeEntry, rules scope.Rules, workers bool) {
	held := heldTargets(rep.Skipped)
	listed := 0 // the held URLs the skipped list names that were not sent as well
	for key := range held {
		if !egress.WasSent(key) {
			listed++
		}
	}
	var all []stateChangeEntry
	for _, e := range mergeStateChanges(pre, found) {
		if rules.DeniedPath(e.URL) != "" {
			continue
		}
		key := normKey(e.URL)
		switch _, isHeld := held[key]; {
		case egress.WasSent(key):
			e.Status = stateSent
		case isHeld:
			e.Status, e.Send = stateHeld, neterr.SendFlag
		case workers:
			e.Status = stateUnknown // a worker's requests are in its own ledger
		default:
			e.Status = stateNotAsked
		}
		delete(held, key)
		all = append(all, e)
	}
	// Held URLs no row or description names: the built-in list's words.
	for _, s := range rep.Skipped {
		key := normKey(s.Target)
		w, ok := held[key]
		if !egress.IsHeldReason(s.Reason) || !ok {
			continue
		}
		delete(held, key)
		all = append(all, stateChangeEntry{Target: s.Target, Method: "GET", URL: s.Target, Word: w, Source: "its path",
			DenyPath: denyRuleFor(s.Target), Status: stateHeld, Send: neterr.SendFlag})
	}
	all = mergeStateChanges(all)
	for _, e := range all {
		if e.Status == stateHeld {
			rep.StateChangingHeld++
		}
	}
	// Each one the run sent or found without asking is a note; the held ones
	// are one note, for there may be many and the skipped list names each.
	named := map[string]bool{}
	for _, e := range pre {
		named[e.Method+" "+e.URL] = true
	}
	for _, e := range all {
		if e.Status == stateHeld || named[e.Method+" "+e.URL] && e.Status == stateSent {
			continue
		}
		rep.Notes = append(rep.Notes, e.line())
	}
	if n := rep.StateChangingHeld; n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%s found on the way declare a state change by their own name and were held back, not sent (listed as skipped): %s sends them", plural(n, "GET"), neterr.SendFlag))
	}
	rep.StateChanging = all
	rep.holds("state-changing GETs held back, against the held URLs the skipped list names", rep.StateChangingHeld, listed)
}

// holdStateChanging has the run look for the GETs whose own path or API
// operation declares a state change, to remember which it sent and, with
// hold, to hold back the ones found on the way. The URLs among the seeds
// are the user's targets: they are never held back.
func holdStateChanging(seeds []types.Seed, hold bool) {
	given := map[string]bool{}
	for _, u := range append(givenURLs(seeds), workerGiven...) {
		given[normKey(u)] = true
	}
	egress.SetStateWords(statechange.OfURL, func(raw string) bool { return given[normKey(raw)] }, hold)
}

// givenURLs are the URL targets among seeds.
func givenURLs(seeds []types.Seed) []string {
	var out []string
	for _, s := range seeds {
		if s.Type == types.TypeURL {
			out = append(out, s.Key())
		}
	}
	return out
}
