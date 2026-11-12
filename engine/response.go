package engine

import (
	"encoding/json"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// Response is what the row's answer kept: its response headers, the start
// of its body and when it was asked. A row of a run before this was kept,
// a folded row and a route nothing answered have none.
func (m MapEntry) Response() (fetch.Evidence, bool) {
	var ev fetch.Evidence
	if m.Count > 1 || len(m.answered) == 0 || json.Unmarshal(m.answered, &ev) != nil {
		return fetch.Evidence{}, false
	}
	return ev, ev.Headers != nil || len(ev.Excerpt) > 0 || ev.BodyLength > 0
}
