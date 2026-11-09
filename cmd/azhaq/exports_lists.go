package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/urlcol"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// listOpts narrows and shapes the urls and names exports.
type listOpts struct {
	coverage string // as query -coverage: only rows of these coverages
	json     bool   // one {url|name, coverage, status, source} object per line
}

var coverages = []string{"visited", "catchall", "error", "gone", "hint", "skipped", "capped"}

// checkCoverage refuses a coverage no row can have: a typo would write an
// empty list that reads as "nothing found".
func checkCoverage(list string) error {
	for _, c := range splitList(list) {
		ok := false
		for _, k := range coverages {
			ok = ok || strings.EqualFold(c, k)
		}
		if !ok {
			return usagef("-coverage %q: use %s", c, strings.Join(coverages, ", "))
		}
	}
	return nil
}

// listLine writes one entry: the bare key, or its JSON object.
func (o listOpts) line(w io.Writer, field, key, cov string, status int, source string) {
	if o.json {
		b, _ := json.Marshal(map[string]any{field: key, "coverage": cov, "status": status, "source": source})
		fmt.Fprintf(w, "%s\n", b)
		return
	}
	fmt.Fprintln(w, key)
}

// exportURLs writes every URL the workspace learned: the map's rows, then
// the rest of what the archives gave, which the workspace keeps in a list
// beside it. An archived URL no request was made for is a hint.
func exportURLs(g *graphView, path string, o listOpts, w io.Writer) error {
	seen := map[string]bool{}
	for _, r := range g.rows {
		if r.Entity.Type != types.TypeURL || seen[r.Entity.Key] {
			continue
		}
		seen[r.Entity.Key] = true
		if inList(o.coverage, r.Coverage) {
			o.line(w, "url", r.Entity.Key, r.Coverage, r.Status, strings.Join(r.EvidenceFrom, ","))
		}
	}
	listed := false
	if err := urlcol.ReadArchive(urlcol.ArchivePath(path), g.run, func(u, source string) {
		listed = true
		if !seen[u] {
			seen[u] = true
			if inList(o.coverage, "hint") {
				o.line(w, "url", u, "hint", 0, source)
			}
		}
	}); err != nil {
		return err
	}
	if !listed {
		if n := urlcol.Held(g.obs, false); n != "" {
			fmt.Fprintf(os.Stderr, "azhaq export: %s\n", n)
		}
	}
	return nil
}

// coverageOrder ranks the coverages of a name's URLs: the best one stands
// for the name.
var coverageOrder = map[string]int{"visited": 0, "catchall": 1, "gone": 2, "error": 3, "skipped": 4, "capped": 5, "hint": 6}

// nameCoverage is what the run did with each name: the best coverage among
// the URLs it holds on that name (visited, catchall, gone, error, skipped,
// capped), with that URL's status; a name no URL was asked on is a hint.
func nameCoverage(rows []engine.MapEntry) map[string]engine.MapEntry {
	best := map[string]engine.MapEntry{}
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL {
			continue
		}
		h := normalize.HostFromURL(r.Entity.Key)
		b, ok := best[h]
		switch {
		case !ok, coverageOrder[r.Coverage] < coverageOrder[b.Coverage]:
		case coverageOrder[r.Coverage] == coverageOrder[b.Coverage] && !frontPage(b.Entity.Key) && frontPage(r.Entity.Key):
		default:
			continue
		}
		best[h] = r
	}
	return best
}

func frontPage(key string) bool {
	u, err := url.Parse(key)
	return err == nil && (u.Path == "" || u.Path == "/")
}

// exportNames writes every hostname in the graph, resolved or not.
func exportNames(g *graphView, o listOpts, w io.Writer) {
	best := nameCoverage(g.rows)
	type name struct {
		key, cov, source string
		status           int
	}
	var names []name
	for _, r := range g.rows {
		if r.Entity.Type != types.TypeHostname {
			continue
		}
		n := name{key: r.Entity.Key, cov: "hint", source: strings.Join(r.EvidenceFrom, ",")}
		if b, ok := best[n.key]; ok {
			n.cov, n.status = b.Coverage, b.Status
		}
		if inList(o.coverage, n.cov) {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i].key < names[j].key })
	for _, n := range names {
		o.line(w, "name", n.key, n.cov, n.status, n.source)
	}
}
