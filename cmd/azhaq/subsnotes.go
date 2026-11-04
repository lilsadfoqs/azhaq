package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// The tiers of a name, in the order a name climbs them. A raw candidate is
// a name a source gave (or the history held): no lookup has confirmed it.
// DNS-confirmed names resolved; HTTP-confirmed ones also answered a request.
// A row's "tier" is the highest tier it reached.
const (
	tierCandidate = "candidate"
	tierDNS       = "dns"
	tierHTTP      = "http"
	countRaw      = "raw candidates"
	countDNS      = "DNS-confirmed"
	countHTTP     = "HTTP-confirmed"
)

// tierSet is a tier's name, as the counts and notes call it, and the names
// that reached it; nil is every name the sources gave.
type tierSet struct {
	name  string
	names map[string]bool
}

// tierNote is the line that says how many names each tier holds and which
// ones were not asked.
func tierNote(c map[string]int, dns bool) []string {
	parts := []string{fmt.Sprintf("%d raw candidates (what the sources gave; a row's sources say who)", c[countRaw])}
	if dns {
		parts = append(parts, fmt.Sprintf("%d DNS-confirmed (resolved)", c[countDNS]))
	} else {
		parts = append(parts, "DNS-confirmed not asked (-live)")
	}
	if n, ok := c[countHTTP]; ok {
		parts = append(parts, fmt.Sprintf("%d HTTP-confirmed (answered a request)", n))
	} else {
		parts = append(parts, "HTTP-confirmed not asked (-http)")
	}
	return []string{"tiers: " + strings.Join(parts, "; ") + ": a candidate is never counted as confirmed"}
}

// subsNotes are the notes subs adds from the sources' payloads: how complete
// the result is in each tier, and a name history that could not be written.
// The coverage of a tier counts only the names that reached it.
func subsNotes(ps []map[string]any, tiers []tierSet) []string {
	dep := subcol.Dependent()
	var notes []string
	notes = append(notes, historyNotes(ps)...)
	for _, t := range tiers {
		var observed, f1, f2 int
		var estimated float64
		for _, p := range ps {
			foundBy := map[string][]string{}
			raw, _ := p["found_by"].(map[string]any)
			for name, by := range raw {
				foundBy[name] = strs(by)
			}
			var filter func(string) bool
			if t.names != nil {
				filter = func(n string) bool { return t.names[n] }
			}
			if s, est, a, b, ok := subcol.Chao1Basis(foundBy, dep, filter); ok {
				observed += s
				estimated += est
				f1 += a
				f2 += b
			}
		}
		if observed == 0 {
			continue
		}
		// What the sources know comes first, and no lone percentage that
		// reads as "this share of the subdomains".
		note := fmt.Sprintf("coverage (%s): what the independent sources know, not every name that exists. Their pool holds about %d names and this run has %d of them",
			t.name, int(estimated+0.5), observed)
		if t.names != nil && len(t.names) > observed {
			// Reconciles with the count printed: the rest have no
			// independent source to estimate from.
			note += fmt.Sprintf(". Apart from the pool, the other %d of the %d names in this tier came from the name history, from guesses checked in DNS or as CNAME targets", len(t.names)-observed, len(t.names))
		}
		// An estimate, and what it rests on: the pool is Chao1's S + f1²/(2·f2)
		// over the names the independent sources gave, so it is as good as the
		// overlap of those sources.
		note += fmt.Sprintf(". This is an estimate (Chao1) from the %d names the independent sources gave: %d came from one source and %d from two", observed, f1, f2)
		notes = append(notes, note)
	}
	return notes
}

// namesKept says which names the history keeps, and how to leave it out.
const namesKept = "it keeps the names the sources gave and the history's own that resolved, not -w, -permute or CNAME-target names; -no-history leaves it alone"

// historyNotes say when a run read or wrote the name history file: the
// path, the names read (given back to be checked) and the names written; a
// file that could not be written is a note too.
func historyNotes(ps []map[string]any) []string {
	var notes, paths []string
	var read, wrote int
	for _, p := range ps {
		if msg, _ := p["history_error"].(string); msg != "" {
			notes = append(notes, "name history not saved: "+msg)
		}
		if h, _ := p[subcol.HistoryKey].(map[string]any); h != nil {
			path, _ := h["path"].(string)
			paths = append(paths, path)
			read += intOf(h["read"])
			wrote += intOf(h["stored"])
			if len(ps) <= 3 {
				notes = append(notes, fmt.Sprintf("name history %s: %d names read, %d written; %s", path, intOf(h["read"]), intOf(h["stored"]), namesKept))
			}
		}
	}
	if len(paths) > 0 && len(ps) > 3 {
		notes = append(notes, fmt.Sprintf("name history (%s, one file per domain): %d names read for %d domains, %d written; %s", filepath.Dir(paths[0]), read, len(paths), wrote, namesKept))
	}
	return notes
}

// historyWrote lists the history files a run wrote: the ones it stored a
// name in.
func historyWrote(ps []map[string]any) []string {
	var paths []string
	for _, p := range ps {
		if h, _ := p[subcol.HistoryKey].(map[string]any); h != nil && intOf(h["stored"]) > 0 {
			path, _ := h["path"].(string)
			paths = append(paths, path)
		}
	}
	return paths
}

// subdomainPayloads are the newest payload of azhaq-subdomains for each
// domain in obs.
func subdomainPayloads(obs []types.StoredObservation) []map[string]any {
	at := map[string]int{}
	var out []map[string]any
	for _, o := range obs {
		var p map[string]any
		if o.Collector != "azhaq-subdomains" || o.Kind != "subdomains" || json.Unmarshal(o.Payload, &p) != nil {
			continue
		}
		d, _ := p["domain"].(string)
		if i, ok := at[d]; ok {
			out[i] = p
			continue
		}
		at[d] = len(out)
		out = append(out, p)
	}
	return out
}

// answeredNames are the hostnames a web request got an answer from, any
// status: the service is there. Names whose requests failed are not in it.
func answeredNames(st *store.Store) map[string]bool {
	out := map[string]bool{}
	obs, _ := st.Observations()
	for _, o := range obs {
		if o.Collector != "azhaq-http" || o.Kind != "application" {
			continue
		}
		var p struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Status == 0 {
			continue
		}
		if h := normalize.HostFromURL(p.URL); h != "" {
			out[h] = true
		}
	}
	return out
}
