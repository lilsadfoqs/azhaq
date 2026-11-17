package hunt

import (
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
)

// A path whose answer is also its prefix's catch-all is a row like any other,
// with the label as a reason, and ranks after the paths that answered for
// themselves, whatever its words would score; an unlabelled 500 of the same
// words keeps its place.
func TestPrefixCatchAllRowRanksLast(t *testing.T) {
	label := "the answer of /rest/user/<random> too: this prefix's catch-all"
	rows := build(
		urlRow("http://app/rest/user/login", "api", "visited", 500, func(r *engine.MapEntry) {
			r.PrefixCatchAll, r.Answer = "http://app/rest/user/k2x9", label
		}),
		urlRow("http://app/admin/login", "page", "visited", 500, nil),
		urlRow("http://app/api/search", "api", "visited", 200, nil),
	)
	if len(rows) != 3 || rows[2].Key != "http://app/rest/user/login" {
		t.Fatalf("the labelled row is last: %+v", rows)
	}
	var got bool
	for _, r := range rows[2].Reasons {
		got = got || r.Signal == "prefix-catchall" && strings.Contains(r.Detail, "this prefix's catch-all")
	}
	if !got {
		t.Errorf("the row says why it is last: %+v", rows[2].Reasons)
	}
	for _, r := range rows[:2] {
		for _, why := range r.Reasons {
			if why.Signal == "prefix-catchall" {
				t.Errorf("%s labelled", r.Key)
			}
		}
	}
}
