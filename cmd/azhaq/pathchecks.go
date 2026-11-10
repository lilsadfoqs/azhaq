package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	"github.com/lilsadfoqs/azhaq/types"
)

// pathCheck is what became of the built-in path checks of one web service:
// listed = sent + already_answered + skipped (with a sweep on record). A check is answered when a
// request sent before (the page, the favicon) already had its answer, so none
// is sent again.
type pathCheck struct {
	Service  string `json:"service"`
	Listed   int    `json:"listed"`
	Sent     *int   `json:"sent,omitempty"` // absent when no sweep of the service is on record
	Answered int    `json:"already_answered,omitempty"`
	Skipped  int    `json:"skipped,omitempty"`
	Reason   string `json:"reason,omitempty"` // why the skipped were, with how many each
	left     bool   // its sweep is among the work the run left for azhaq resume
}

// pathChecks says, for each web service the run reached, what became of the
// checks the plan lists for it (list). A service whose sweep left no record
// says so: its checks were listed and no request of the sweep is on record.
func pathChecks(obs []types.StoredObservation, list []string, failed map[string]string, left map[string]bool) []pathCheck {
	if len(list) == 0 {
		return nil
	}
	by := map[string]*pathCheck{}
	var order []string
	add := func(origin string) *pathCheck {
		if c := by[origin]; c != nil {
			return c
		}
		by[origin] = &pathCheck{Service: origin}
		order = append(order, origin)
		return by[origin]
	}
	for _, o := range obs {
		if o.Collector != pathscol.Name || o.Kind != pathscol.SweepKind {
			continue
		}
		var p struct {
			Origin    string         `json:"origin"`
			Planned   int            `json:"planned"`
			Sent      int            `json:"sent"`
			Answered  int            `json:"answered"`
			Described int            `json:"described"`
			Refused   map[string]int `json:"refused"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Origin == "" {
			continue
		}
		c := add(p.Origin)
		sent := p.Sent
		c.Listed, c.Sent, c.Answered = p.Planned, &sent, p.Answered
		var why []string
		if p.Described > 0 {
			why = append(why, fmt.Sprintf("an API description was already found (%d)", p.Described))
		}
		left := p.Planned - p.Sent - p.Answered - p.Described
		for _, r := range sortedStringKeys(p.Refused) {
			why = append(why, fmt.Sprintf("%s (%d)", r, p.Refused[r]))
			left -= p.Refused[r]
		}
		if left > 0 {
			why = append(why, fmt.Sprintf("the sweep was stopped before it asked them (%d)", left))
		}
		c.Skipped = p.Planned - p.Sent - p.Answered
		c.Reason = strings.Join(why, "; ")
	}
	// The web services that answered and have no sweep on record.
	for _, o := range obs {
		if o.Collector != "azhaq-http" || o.Kind != "application" {
			continue
		}
		var p struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" || by[u.Scheme+"://"+u.Host] != nil {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		c := add(origin)
		locs, descs := pathscol.Sweep(origin+"/", list)
		c.Listed = len(locs) + len(descs)
		c.Reason = "its sweep left no record: it did not run, or the run ended before it finished (see stopped and failed)"
		if left[origin] {
			c.Reason, c.left = "its sweep is among the work the run left (found past -depth or over a cap, see notes): azhaq resume sweeps it", true
		}
		if e := failed[origin]; e != "" {
			c.Reason = "its sweep failed: " + e
		}
	}
	sort.Strings(order)
	out := make([]pathCheck, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out
}

func sortedStringKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pathCheckNotes name the services that did not get all their checks for a
// reason the description note does not give: its count is of the checks an
// API description made unnecessary.
func pathCheckNotes(cs []pathCheck) []string {
	var out []string
	for _, c := range cs {
		switch {
		case c.Sent == nil:
			out = append(out, fmt.Sprintf("path checks on %s: %d listed; %s", c.Service, c.Listed, c.Reason))
		case c.Skipped > 0 && (!strings.HasPrefix(c.Reason, "an API description was already found") || strings.Contains(c.Reason, "; ")):
			out = append(out, fmt.Sprintf("path checks on %s: %d of the %d listed were not sent: %s", c.Service, c.Skipped, c.Listed, c.Reason))
		}
	}
	return out
}

// failUnrecordedSweeps fails closed: a sweep the run listed that left no
// record, with no stop to explain it, is a failure that makes the run
// incomplete (exit 3). A stopped run has the work left to resume instead.
func (r *report) failUnrecordedSweeps() {
	if r.Stopped != "" {
		return
	}
	named := map[string]bool{}
	for _, f := range r.Failed {
		if f.Collector == pathscol.Name {
			for _, t := range f.Targets {
				named[t] = true
			}
		}
	}
	for _, c := range r.PathChecks {
		if c.Sent != nil || c.left || named[c.Service] || strings.HasPrefix(c.Reason, "its sweep failed") {
			continue
		}
		r.Failed = append(r.Failed, engine.Failure{
			Collector: pathscol.Name, Error: "its sweep left no record, and no limit stopped the run: it did not run",
			Retryable: true, Count: 1, Targets: []string{c.Service},
		})
		r.warned = true
	}
}

// leftOrigins are the web services with a URL among the work a run left
// (past -depth, over a cap): their sweep is for azhaq resume, not missing.
func leftOrigins(left []types.Seed) map[string]bool {
	out := map[string]bool{}
	for _, s := range left {
		if s.Type != types.TypeURL {
			continue
		}
		if u, err := url.Parse(s.Keys["url"]); err == nil && u.Host != "" {
			out[u.Scheme+"://"+u.Host] = true
		}
	}
	return out
}

// failedPaths are the errors of the path sweeps that failed, by origin.
func failedPaths(failed []engine.Failure) map[string]string {
	out := map[string]string{}
	for _, f := range failed {
		if f.Collector != pathscol.Name {
			continue
		}
		for _, t := range f.Targets {
			if u, err := url.Parse(t); err == nil && u.Host != "" {
				out[u.Scheme+"://"+u.Host] = f.Error
			}
		}
	}
	return out
}
