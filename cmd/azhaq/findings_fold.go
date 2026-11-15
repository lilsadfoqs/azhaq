package main

import (
	"sort"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
)

// foldAnswers folds the findings and leads of one URL that answered the same at
// another name of the same address and port into the first of them (a URL the
// target scope holds first, then by URL: hunt's order). It keeps one record and
// lists the other URLs in its Also. The rule is hunt's own (hunt.AnswerSig), so
// report, export and hunt list one row for one service. A record with no URL,
// or whose answer was not read on both names, is not folded: nothing shows
// the two equal.
func foldAnswers(rows []engine.MapEntry, addrs, hashes map[string]string, recs []findingRecord) []findingRecord {
	if len(recs) < 2 {
		return recs
	}
	status, scope := map[string]int{}, map[string]string{}
	for _, r := range rows {
		status[r.Entity.Key], scope[r.Entity.Key] = r.Status, r.Scope
	}
	type item struct {
		at  int
		key string
	}
	groups := map[string][]item{}
	for i, r := range recs {
		if r.URL == "" || r.Collector == "azhaq-verify" {
			continue
		}
		sig := hunt.AnswerSig(r.URL, status[r.URL], hashes[r.URL], addrs)
		if sig == "" {
			continue
		}
		excerpt := ""
		if r.Proof != nil {
			excerpt = r.Proof.Excerpt
		}
		// What else must be equal: the same kind of record about the same
		// thing (two secrets of one script are two records).
		k := r.Tier + "\x00" + r.Kind + "\x00" + r.Label + "\x00" + r.Product + "\x00" + excerpt + "\x00" + sig
		groups[k] = append(groups[k], item{i, k})
	}
	drop := map[int]bool{}
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		sort.SliceStable(g, func(a, b int) bool {
			ua, ub := recs[g[a].at].URL, recs[g[b].at].URL
			if (scope[ua] == "target") != (scope[ub] == "target") {
				return scope[ua] == "target"
			}
			return ua < ub
		})
		first := &recs[g[0].at]
		for _, it := range g[1:] {
			o := recs[it.at]
			if o.URL == first.URL {
				continue
			}
			first.Also = append(first.Also, o.URL)
			first.Also = append(first.Also, o.Also...)
			drop[it.at] = true
		}
		sort.Strings(first.Also)
	}
	if len(drop) == 0 {
		return recs
	}
	out := recs[:0:0]
	for i, r := range recs {
		if !drop[i] {
			out = append(out, r)
		}
	}
	return out
}
