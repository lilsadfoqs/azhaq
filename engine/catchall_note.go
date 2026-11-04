package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"sort"

	"github.com/lilsadfoqs/azhaq/types"
)

// CatchAllHeldReason is why a URL a script names was not requested: its
// origin had answered other paths with the page every unknown path gets.
const CatchAllHeldReason = "the origin answers unknown paths with one page (-catchall-after 0 asks every path)"

// CatchAllHeldNotes says, for each origin, how many URLs scripts name were not
// asked because it had answered paths with its catch-all page.
func CatchAllHeldNotes(rows []MapEntry, obs []types.StoredObservation) []string {
	held := CatchAllHeldIDs(obs)
	if len(held) == 0 {
		return nil
	}
	notAsked, answers := map[string]int{}, map[string]int{}
	for _, r := range rows {
		if r.Entity.Type != types.TypeURL {
			continue
		}
		switch {
		case held[r.Entity.ID] && r.Coverage == "skipped":
			notAsked[originOf(r.Entity.Key)]++
		case r.Coverage == "catchall":
			answers[originOf(r.Entity.Key)]++
		}
	}
	var out []string
	for _, o := range slices.Sorted(maps.Keys(notAsked)) {
		note := fmt.Sprintf("%s: %d URLs that scripts name were not asked, because it had answered paths with the one page every unknown path gets", o, notAsked[o])
		if n := answers[o]; n > 0 {
			note = fmt.Sprintf("%s: %d URLs that scripts name were not asked, because it had answered %d paths with the one page every unknown path gets", o, notAsked[o], n)
		}
		out = append(out, note+" (-catchall-after 0 asks every path; their rows are coverage skipped)")
	}
	return out
}

// CatchAllHeldIDs are the entities of the URLs not asked for that reason.
func CatchAllHeldIDs(obs []types.StoredObservation) map[string]bool {
	held := map[string]bool{}
	for _, o := range obs {
		if o.Kind != "skipped" {
			continue
		}
		var p struct {
			Skipped string `json:"skipped"`
		}
		if json.Unmarshal(o.Payload, &p) == nil && p.Skipped == CatchAllHeldReason {
			held[o.EntityID] = true
		}
	}
	return held
}

// CatchAllNotes say which origins answered three or more URLs with the
// page every unknown path gets (an app shell), so a 200 there is not read
// as a route that exists. A bare address gets the lead that its name may
// be served differently.
func CatchAllNotes(rows []MapEntry) []string {
	const most, min = 3, 3
	n := map[string]int{}
	for _, r := range rows {
		if r.Entity.Type == types.TypeURL && r.Coverage == "catchall" {
			n[originOf(r.Entity.Key)]++
		}
	}
	var origins []string
	for o, c := range n {
		if c >= min {
			origins = append(origins, o)
		}
	}
	sort.Slice(origins, func(i, j int) bool {
		if n[origins[i]] != n[origins[j]] {
			return n[origins[i]] > n[origins[j]]
		}
		return origins[i] < origins[j]
	})
	var out []string
	for i, o := range origins {
		if i == most {
			break
		}
		note := fmt.Sprintf("%s answered %d URLs with the page it gives a path that cannot exist (coverage catchall): a 200 there does not show that a route exists", o, n[o])
		if u, err := url.Parse(o); err == nil && net.ParseIP(u.Hostname()) != nil {
			note += "; an address may serve another site than its name does, so ask it with the name (-H 'Host: NAME')"
		}
		out = append(out, note)
	}
	return out
}
