package engine

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// The classes of the default view: a URL row that answers for itself is
// listed, and a row that the run's own requests show to say nothing of a
// route is counted in one line of its class. Every class follows from an
// answer the run got or a request it did not send; none from a name.
const (
	// FoldCatchAll: the answer is the one the origin gives a path that
	// cannot exist (the control request's), or the URL was not asked because
	// the origin had answered other paths so.
	FoldCatchAll = "catchall"
	// FoldNotFound: the server answered the URL itself with 404 or 410 (a
	// route only scripts name, whose GET got it, included).
	FoldNotFound = "not-found"
	// FoldBeyondDepth: an image, font or media file (or a map or manifest)
	// a page holds that no request asked for (past -depth, a limit, or
	// fetched by no crawl step). Scripts are code, and stay listed.
	FoldBeyondDepth = "beyond-depth"
	// FoldUnrequested: a string or call only scripts name, that nothing
	// requested and no page, form or description holds.
	FoldUnrequested = "unrequested"
)

// FoldClasses is the classes in the order they are listed.
var FoldClasses = []string{FoldCatchAll, FoldNotFound, FoldBeyondDepth, FoldUnrequested}

// Folder sorts the URL rows of a run into the default view's classes. The
// zero value folds nothing it needs the run for (the rows held back for a
// catch-all origin, the controls); NewFolder reads those.
type Folder struct {
	held     map[string]bool // entity IDs of URLs not asked: their origin answers every path alike
	controls map[string][]fetch.Control
}

// NewFolder reads from the run's observations which URLs were held back
// for a catch-all origin and which control requests its catch-all answers
// were compared with.
func NewFolder(obs []types.StoredObservation) *Folder {
	f := &Folder{held: CatchAllHeldIDs(obs), controls: map[string][]fetch.Control{}}
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Kind != "application" {
			continue
		}
		var p struct {
			URL      string         `json:"url"`
			CatchAll bool           `json:"catchall"`
			Control  *fetch.Control `json:"control"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || !p.CatchAll || p.Control == nil || p.Control.URL == "" {
			continue
		}
		origin := originOf(p.URL)
		if k := origin + " " + p.Control.URL; !seen[k] {
			seen[k] = true
			f.controls[origin] = append(f.controls[origin], *p.Control)
		}
	}
	for _, cs := range f.controls {
		slices.SortFunc(cs, func(a, b fetch.Control) int { return cmp.Compare(a.URL, b.URL) })
	}
	return f
}

// Class is the fold class of a row: "" for a row that is listed.
func (f *Folder) Class(r MapEntry) string {
	if r.Entity.Type != types.TypeURL {
		return ""
	}
	switch {
	case r.Coverage == "catchall", r.Coverage == "skipped" && f != nil && f.held[r.Entity.ID]:
		return FoldCatchAll
	case r.Coverage == "gone", scriptsOnly404(r):
		return FoldNotFound
	case (r.Coverage == "hint" || r.Coverage == "capped") && assetRole(r.Role):
		return FoldBeyondDepth
	case scriptHint(r):
		return FoldUnrequested
	}
	return ""
}

func assetRole(role string) bool {
	switch role {
	case "asset", "sourcemap", "manifest":
		return true
	}
	return false
}

// scriptsOnly404 is a route only scripts name, with no call to say how it is
// used, whose GET answered 404 or 410: the map keeps it a hint, since a script
// may POST to it, and the answer it got is the one the class counts.
func scriptsOnly404(r MapEntry) bool {
	return r.Coverage == "hint" && (r.Status == 404 || r.Status == 410) && strings.HasSuffix(r.Proof, ProofScriptsOnly)
}

// scriptHint is a hint only scripts name that no request asked for, with no
// description, page link, form or archive to hold it.
func scriptHint(r MapEntry) bool {
	if r.Coverage != "hint" || r.Status != 0 || r.Role == "client-route" || r.Role == "websocket" {
		return false
	}
	if r.Evidence != EvLinked && r.Evidence != EvCalled || len(r.EvidenceFrom) == 0 || len(r.Forms) > 0 || len(r.Methods) > 0 {
		return false
	}
	return !slices.ContainsFunc(r.EvidenceFrom, func(c string) bool { return c != "azhaq-js" })
}

// Split separates the rows to list from the folded ones, each in its order.
func (f *Folder) Split(rows []MapEntry) (listed, folded []MapEntry) {
	for _, r := range rows {
		if f.Class(r) == "" {
			listed = append(listed, r)
		} else {
			folded = append(folded, r)
		}
	}
	return listed, folded
}

// FoldTemplate is a URL template and how many folded rows share it.
type FoldTemplate struct {
	Template string `json:"template"`
	Count    int    `json:"count"`
}

// FoldGroup is one line of the default view: the rows of one class (of
// one origin, for the catch-all) folded into it.
type FoldGroup struct {
	Class  string `json:"class"`
	Origin string `json:"origin,omitempty"` // catchall: the origin whose answers these are
	Count  int    `json:"count"`            // the rows
	// NotAsked is how many of Count were never requested: for a catch-all
	// origin, the URLs held back; for beyond-depth and unrequested, all.
	NotAsked int `json:"not_asked,omitempty"`
	// Controls are the requests for a path that cannot exist that the
	// origin's catch-all answers were compared with, and what they answered.
	Controls []fetch.Control `json:"controls,omitempty"`
	// Statuses (not-found): the answers the rows got.
	Statuses map[int]int `json:"statuses,omitempty"`
	// Templates are the most common templates of the rows, Templated how
	// many distinct templates they have.
	Templates []FoldTemplate `json:"templates,omitempty"`
	Templated int            `json:"templated,omitempty"`
	Origins   int            `json:"origins,omitempty"` // origins the rows are of, when more than one
}

const foldTemplates = 5

// Groups counts the folded rows by class, in the order of FoldClasses; a
// catch-all origin is a group of its own, as each has its own control.
func (f *Folder) Groups(rows []MapEntry) []FoldGroup {
	type key struct{ class, origin string }
	idx := map[key]*FoldGroup{}
	tmpl := map[key]map[string]int{}
	var order []key
	for _, r := range rows {
		class := f.Class(r)
		if class == "" {
			continue
		}
		k := key{class: class}
		if class == FoldCatchAll {
			k.origin = originOf(r.Entity.Key)
		}
		g := idx[k]
		if g == nil {
			g = &FoldGroup{Class: class, Origin: k.origin}
			if class == FoldCatchAll {
				g.Controls = f.controls[k.origin]
			}
			if class == FoldNotFound {
				g.Statuses = map[int]int{}
			}
			idx[k] = g
			tmpl[k] = map[string]int{}
			order = append(order, k)
		}
		g.Count++
		switch {
		case r.Coverage == "skipped" || r.Coverage == "hint" || r.Coverage == "capped":
			g.NotAsked++
		}
		if r.Status > 0 && g.Statuses != nil {
			g.Statuses[r.Status]++
		}
		tmpl[k][webextract.Template(r.Entity.Key)]++
	}
	out := make([]FoldGroup, 0, len(order))
	for _, k := range order {
		g := idx[k]
		var ts []FoldTemplate
		for t, n := range tmpl[k] {
			ts = append(ts, FoldTemplate{Template: t, Count: n})
		}
		slices.SortFunc(ts, func(a, b FoldTemplate) int {
			if a.Count != b.Count {
				return cmp.Compare(b.Count, a.Count)
			}
			return cmp.Compare(a.Template, b.Template)
		})
		g.Templated = len(ts)
		seen := map[string]bool{}
		for _, t := range ts {
			seen[originOf(t.Template)] = true
		}
		if len(seen) > 1 {
			g.Origins = len(seen)
		}
		if len(ts) > foldTemplates {
			ts = ts[:foldTemplates]
		}
		g.Templates = ts
		out = append(out, *g)
	}
	slices.SortStableFunc(out, func(a, b FoldGroup) int {
		return cmp.Compare(slices.Index(FoldClasses, a.Class), slices.Index(FoldClasses, b.Class))
	})
	return out
}

// Line is the group as one line of the default view.
func (g FoldGroup) Line() string {
	n := func(c int, what string) string {
		if c == 1 {
			return "1 " + what
		}
		return fmt.Sprintf("%d %ss", c, what)
	}
	switch g.Class {
	case FoldCatchAll:
		line := fmt.Sprintf("folded catchall: %s of %s answer as the control does", n(g.Count, "URL"), g.Origin)
		if g.NotAsked > 0 {
			line += fmt.Sprintf(" (%d not asked: the origin had answered paths so)", g.NotAsked)
		}
		if len(g.Controls) == 0 {
			return line
		}
		var cs []string
		for i, c := range g.Controls {
			if i == 3 {
				cs = append(cs, fmt.Sprintf("%d more", len(g.Controls)-3))
				break
			}
			cs = append(cs, c.String())
		}
		return line + ": " + strings.Join(cs, "; ")
	case FoldNotFound:
		line := fmt.Sprintf("folded not-found: %s answered 404 or 410, in %s", n(g.Count, "URL"), n(g.Templated, "template"))
		var ts []string
		for _, t := range g.Templates {
			ts = append(ts, fmt.Sprintf("%s ×%d", t.short(g.Origins <= 1), t.Count))
		}
		if len(ts) > 0 {
			line += ": " + strings.Join(ts, ", ")
			if g.Templated > len(g.Templates) {
				line += fmt.Sprintf(", and %d more", g.Templated-len(g.Templates))
			}
		}
		return line
	case FoldBeyondDepth:
		return fmt.Sprintf("folded beyond-depth: %s (images, fonts, media, maps) pages hold that no request asked for", n(g.Count, "asset"))
	}
	return fmt.Sprintf("folded unrequested: %s only scripts name, that nothing requested", n(g.Count, "URL"))
}

// short is the template without its origin, when the rows are of one.
func (t FoldTemplate) short(one bool) string {
	if one {
		return strings.TrimPrefix(t.Template, originOf(t.Template))
	}
	return t.Template
}
