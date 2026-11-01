package main

import (
	"fmt"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// subsNotes are the notes subs adds from the sources' payloads: how complete
// the result is, and a name history that could not be written. keep, if
// set, limits the coverage to the names printed (-live).
func subsNotes(ps []map[string]any, keep map[string]bool) []string {
	dep := subcol.Dependent()
	var notes []string
	var observed int
	var estimated float64
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
		if msg, _ := p["history_error"].(string); msg != "" {
			notes = append(notes, "name history not saved: "+msg)
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
