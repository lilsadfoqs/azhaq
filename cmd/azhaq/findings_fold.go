package main

import (
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/internal/productname"
	"github.com/lilsadfoqs/azhaq/internal/verify"
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

// foldVerifyResults makes one result of the results of one listener (address
// and port) that read the same: the same check, label, product, version, request
// and answer. A workspace stored before a read stood for every name holds one
// per name. The result kept is the first name's (a name before an address), and
// Names lists the others. Results whose answers differ are not folded.
func foldVerifyResults(rs []verify.Result, addrs map[string]string) []verify.Result {
	if len(rs) < 2 {
		return rs
	}
	listener := func(r verify.Result) string {
		h := strings.ToLower(r.Host)
		if a, err := netip.ParseAddr(h); err == nil {
			h = a.Unmap().String()
		} else if a := addrs[h]; a != "" {
			h = a
		}
		return h + ":" + strconv.Itoa(r.Port)
	}
	answer := func(r verify.Result) string {
		if r.Proof == nil {
			return r.Evidence // an advisory result: its own text
		}
		return r.Proof.ExcerptPart + r.Proof.Excerpt
	}
	groups := map[string][]int{}
	var order []string
	for i, r := range rs {
		if r.Port == 0 || r.Host == "" {
			continue
		}
		k := strings.Join([]string{listener(r), r.Kind, r.Label, r.AdvisoryID, productname.Canon(r.Product), r.Version, r.Request, answer(r)}, "\x00")
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	drop := map[int]bool{}
	for _, k := range order {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		var names []string
		for _, i := range g {
			for _, n := range append([]string{rs[i].Host}, rs[i].Names...) {
				if !slices.ContainsFunc(names, func(x string) bool { return strings.EqualFold(x, n) }) {
					names = append(names, n)
				}
			}
		}
		sort.Strings(names)
		first := advisory.FirstName(names)
		keep := g[0]
		for _, i := range g {
			if strings.EqualFold(rs[i].Host, first) {
				keep = i
				break
			}
		}
		for _, i := range g {
			if i != keep {
				drop[i] = true
			}
		}
		rs[keep].Names = names
	}
	if len(drop) == 0 {
		return rs
	}
	out := rs[:0:0]
	for i, r := range rs {
		if !drop[i] {
			out = append(out, r)
		}
	}
	return out
}
