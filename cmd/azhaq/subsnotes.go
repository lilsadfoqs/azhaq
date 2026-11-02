package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/types"
)

// subsNotes are the notes subs adds from the sources' payloads: how complete
// the result is, and a name history that could not be written. keep, if
// set, limits the coverage to the names printed (-live).
func subsNotes(ps []map[string]any, keep map[string]bool) []string {
	dep := subcol.Dependent()
	var notes []string
	var observed int
	var estimated float64
	notes = append(notes, historyNotes(ps)...)
	for _, p := range ps {
		foundBy := map[string][]string{}
		raw, _ := p["found_by"].(map[string]any)
		for name, by := range raw {
			foundBy[name] = strs(by)
		}
		var filter func(string) bool
		if keep != nil {
			filter = func(n string) bool { return keep[n] }
		}
		if s, est, ok := subcol.Chao1(foundBy, dep, filter); ok {
			observed += s
			estimated += est
		}
	}
	if observed > 0 {
		// What the sources know comes first, and no lone percentage that
		// reads as "this share of the subdomains".
		note := fmt.Sprintf("coverage: what the independent sources know, not every name that exists. Their pool holds about %d names and this run has %d of them",
			int(estimated+0.5), observed)
		if keep != nil && len(keep) > observed {
			// Reconciles with the count printed: the rest have no
			// independent source to estimate from.
			note += fmt.Sprintf(". Apart from the pool, the other %d of the %d names printed came from the name history, from guesses checked in DNS or as CNAME targets", len(keep)-observed, len(keep))
		}
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
		notes = append(notes, fmt.Sprintf("name history (%s, one file per domain): %d names read for %d domains, %d written; %s", filepath.Join(subcol.DataDir(), "names"), read, len(paths), wrote, namesKept))
	}
	return notes
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
