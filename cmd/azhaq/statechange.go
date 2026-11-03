package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/statechange"
	"github.com/lilsadfoqs/azhaq/scope"
	"github.com/lilsadfoqs/azhaq/types"
)

// stateChangeEntry is one GET request whose own name or description
// declares a state change, named before it is sent (in a plan, and in
// a run's first lines) and, for the ones a run finds on the way, in its
// summary. Nothing is withheld: the entry only names the request and
// the -deny-path rule that would keep it out.
type stateChangeEntry struct {
	Target      string `json:"target"`                // the seed target the request belongs to
	Method      string `json:"method"`                // always GET: the requests azhaq sends without a write flag
	URL         string `json:"url"`                   // the request that would be (or was) sent
	Word        string `json:"word"`                  // the word that declares the change: create, delete, reset, populate, logout, …
	Source      string `json:"source"`                // where the word is: its name, or its API description
	Description string `json:"description,omitempty"` // the operation's own description, when a description gave the word
	DenyPath    string `json:"deny_path"`             // the -deny-path rule that would keep this request out
}

// line is the entry as plan and a run's notes print it.
func (e stateChangeEntry) line() string {
	where := e.Source
	if e.Description != "" {
		where += fmt.Sprintf(" %q", e.Description)
	}
	return fmt.Sprintf("%s %s may change state (the word %q in %s); it is still sent unless a rule keeps it out: keep it out with %s", e.Method, e.URL, e.Word, where, e.DenyPath)
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
// seed whose own path or query names a state change, in scope and not
// already kept out by a -deny-path rule (those are listed as skipped).
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
		text := parsed.Path
		if parsed.RawQuery != "" {
			text += "?" + parsed.RawQuery
		}
		word, ok := statechange.Declares(text)
		if !ok {
			continue
		}
		out = append(out, stateChangeEntry{Target: u, Method: "GET", URL: u, Word: word, Source: "its name", DenyPath: denyRuleFor(u)})
	}
	return out
}

// stateChangesOfOps are the entries in API descriptions a run has
// read: each GET operation whose path, summary, description or
// operationId declares a state change, with the description that
// says so. It is a pure read of the observations, so a description
// produces its entries before any of its operations is requested.
func stateChangesOfOps(obs []types.StoredObservation) []stateChangeEntry {
	var out []stateChangeEntry
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Collector != "azhaq-openapi" || o.Kind != "url" {
			continue
		}
		var p struct {
			URL string `json:"url"`
			Ops []struct {
				Method      string `json:"method"`
				Summary     string `json:"summary"`
				Description string `json:"description"`
				OperationID string `json:"operation_id"`
				StateChange string `json:"state_change"`
			} `json:"ops"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		for _, op := range p.Ops {
			if op.Method != "GET" {
				continue
			}
			word := op.StateChange
			source := "its API description"
			if word == "" {
				var ok bool
				if word, ok = statechange.Declares(p.URL, op.Summary, op.Description, op.OperationID); !ok {
					continue
				}
			}
			if op.Summary == "" && op.Description == "" && op.OperationID == "" {
				source = "its name in its API description"
			}
			key := "GET " + p.URL
			if seen[key] {
				continue
			}
			seen[key] = true
			desc := op.Description
			if desc == "" {
				desc = op.Summary
			}
			out = append(out, stateChangeEntry{Target: p.URL, Method: "GET", URL: p.URL, Word: word, Source: source, Description: desc, DenyPath: denyRuleFor(p.URL)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// stateChangesOfRows are the entries among the URLs a run found on
// the way (a link named /logout, a script's call): the ones no API
// description named, by their own name alone. Skipped URLs were not
// sent, so they are not entries.
func stateChangesOfRows(rows []mapRowLike) []stateChangeEntry {
	var out []stateChangeEntry
	seen := map[string]bool{}
	for _, r := range rows {
		if r.skipped || seen[r.key] {
			continue
		}
		seen[r.key] = true
		u, err := url.Parse(r.key)
		if err != nil {
			continue
		}
		word, ok := statechange.Declares(u.Path)
		if !ok {
			continue
		}
		out = append(out, stateChangeEntry{Target: r.key, Method: "GET", URL: r.key, Word: word, Source: "its name", DenyPath: denyRuleFor(r.key)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// mapRowLike is the part of a map row the state-change list reads.
type mapRowLike struct {
	key     string
	skipped bool
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
