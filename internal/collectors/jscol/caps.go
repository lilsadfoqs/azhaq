package jscol

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// left is what one page's caps kept this pass from reading.
type left struct {
	scripts                         map[string]bool // script URLs not fetched
	routes, maps, manifests, chunks int
}

// routesIn counts the links among urls that would have been rows.
func routesIn(urls []string) int {
	n := 0
	for _, u := range urls {
		if r := webextract.ClassifyURL(u); r != "asset" && r != "script" {
			n++
		}
	}
	return n
}

// Short is one kind of work the caps left unread, over the pages of a run.
type Short struct {
	What  string // scripts, routes, source maps, build manifests, chunk names
	Limit int    // the cap it hit
	Left  int
	Pages int
}

type capPart struct {
	What  string `json:"what"`
	Limit int    `json:"limit"`
	Left  int    `json:"left"`
}

// note is the observation payload that says what the page's caps left
// unread, or nil when they left nothing.
func (l left) note(page string, lim limits) []byte {
	parts := []capPart{
		{"scripts", lim.scripts, len(l.scripts)},
		{"routes", lim.routes, l.routes},
		{"source maps", lim.maps, l.maps},
		{"build manifests", lim.manifests, l.manifests},
		{"chunk names", lim.chunks, l.chunks},
	}
	var kept []capPart
	var text []string
	for _, p := range parts {
		if p.Left > 0 {
			kept = append(kept, p)
			text = append(text, fmt.Sprintf("%d %s (limit %d)", p.Left, p.What, p.Limit))
		}
	}
	if len(kept) == 0 {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{"url": page, "via": "js", "max_scripts": lim.scripts, "caps": kept,
		"warning": fmt.Sprintf("the scripts of %s hold more than Azhaq reads from one page, so some were left unread: %s (-max-scripts raises the limit on scripts, and the routes, source maps and manifests with it)", page, strings.Join(text, ", "))})
	return payload
}

// ShortOf sums what the pages' caps left unread, kind by kind, from the
// notes the collector wrote; perPage is the -max-scripts the pages had.
func ShortOf(obs []types.StoredObservation) (short []Short, perPage int) {
	idx := map[string]int{}
	for _, o := range obs {
		if o.Collector != Name || o.Kind != "note" {
			continue
		}
		var p struct {
			Max  int       `json:"max_scripts"`
			Caps []capPart `json:"caps"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || len(p.Caps) == 0 {
			continue
		}
		perPage = max(perPage, p.Max)
		for _, c := range p.Caps {
			i, ok := idx[c.What]
			if !ok {
				i = len(short)
				idx[c.What] = i
				short = append(short, Short{What: c.What, Limit: c.Limit})
			}
			short[i].Left += c.Left
			short[i].Pages++
		}
	}
	return short, perPage
}
