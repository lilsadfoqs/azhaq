package main

import (
	"encoding/json"
	"strings"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/collectors/rendercol"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// interactNotRun is the note for a run given -interact that clicked no page:
// a pass that did not run says so, with why. A page that was clicked is
// told of by interactNotes (even when it had nothing to click). stopped is the
// run's stop reason, "" when it was not stopped.
func interactNotRun(obs []types.StoredObservation, stopped string) string {
	failed := 0
	for _, o := range obs {
		if o.Kind == "interact" {
			return ""
		}
		if o.Collector == rendercol.Name && o.Kind == "error" {
			failed++
		}
	}
	const head = "-interact did not run: no page was clicked: "
	switch {
	case stopped != "":
		why, _, _ := strings.Cut(stopped, " (")
		return head + "the run stopped first (" + why + ")"
	case failed > 0:
		return head + plural(failed, "page") + " Chrome tried to load failed (the failures list them)"
	}
	return head + "Chrome loaded no page: no web service of the targets answered with a page to render"
}

// clickRoutes counts the routes only a click named: the rows -browser
// -interact marked as shown by a click alone. A route is the map's route
// identity (webextract.RouteKey; a hash route keeps its fragment): a
// trailing-slash variant of a route something else names is that route. A
// route whose row answered with the catch-all page is no route. left is
// how many addresses a click reached that the count leaves out.
func clickRoutes(obs []types.StoredObservation, rows []engine.MapEntry) (found, left int) {
	catchall := map[string]bool{}
	for _, r := range rows {
		if r.Entity.Type == types.TypeURL && r.Coverage == "catchall" {
			catchall[r.Entity.Key] = true
		}
	}
	identity := func(key, role string) string {
		if role == "client-route" {
			return key
		}
		return webextract.RouteKey(key)
	}
	known := map[string]bool{}
	clicked := map[string]string{} // address -> route identity
	for _, o := range obs {
		var p struct {
			URL, Role string
			Clicked   bool
		}
		if o.Kind != "url" || json.Unmarshal(o.Payload, &p) != nil || p.URL == "" {
			continue
		}
		key, err := engine.FoundKey(p.URL, p.Role)
		if err != nil {
			continue
		}
		if p.Clicked && o.Collector == rendercol.Name {
			clicked[key] = identity(key, p.Role)
		} else {
			known[identity(key, p.Role)] = true
		}
	}
	routes := map[string]bool{}
	for key, id := range clicked {
		if known[id] || catchall[key] {
			left++
			continue
		}
		routes[id] = true
	}
	return len(routes), left
}
