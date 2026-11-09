package main

import (
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/collectors/rendercol"
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
