package engine

import (
	"fmt"
	"net"
	"net/url"
	"sort"

	"github.com/trannghiach/azhaq/types"
)

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
		note := fmt.Sprintf("%s answered %d URLs with the one page every unknown path gets (coverage catchall): a 200 there does not show that a route exists", o, n[o])
		if u, err := url.Parse(o); err == nil && net.ParseIP(u.Hostname()) != nil {
			note += "; an address may serve another site than its name does, so ask it with the name (-H 'Host: NAME')"
		}
		out = append(out, note)
	}
	return out
}
