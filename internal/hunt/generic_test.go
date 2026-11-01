package hunt

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
)

// A site's sign-in and reset pages are assets to note: they are listed,
// below the routes that are a way in.
func TestSignInPagesRankBelowRealSignals(t *testing.T) {
	const o = "http://ci.test:8080"
	form := func(fields ...string) func(*engine.MapEntry) {
		return func(r *engine.MapEntry) {
			r.Params = fields
			r.Forms = []engine.MapForm{{Method: "POST", Fields: fields}}
		}
	}
	rows := build(
		urlRow(o+"/login", "page", "visited", 200, form("j_username", "j_password")),
		urlRow(o+"/login?from={v}", "page", "visited", 200, form("j_username", "j_password")),
		urlRow(o+"/browser/reset_password", "page", "visited", 200, form("csrf_token", "email")),
		urlRow(o+"/user/register", "page", "visited", 200, nil),
		urlRow(o+"/admin", "page", "visited", 200, nil),
		urlRow(o+"/oauth/token", "api", "visited", 200, nil),
	)
	sc := map[string]int{}
	for _, r := range rows {
		sc[strings.TrimPrefix(r.Key, o)] = r.Score
	}
	for _, k := range []string{"/login", "/login?from={v}", "/browser/reset_password", "/user/register"} {
		if sc[k] == 0 {
			t.Errorf("%s is not listed: %v", k, sc)
		}
		if sc[k] >= sc["/admin"] {
			t.Errorf("%s scores %d, not below an admin page (%d): %v", k, sc[k], sc["/admin"], sc)
		}
	}
	if sc["/oauth/token"] < sc["/admin"] {
		t.Errorf("a token endpoint keeps its weight: %v", sc)
	}
	if !has(find(rows, o+"/login"), "path-auth") {
		t.Errorf("the sign-in page keeps its signal: %+v", find(rows, o+"/login"))
	}
}

// A search box every page of a site carries belongs to the site's
// template: the pages that only carry it have no signal, the route that
// takes the name in its own query keeps it.
func TestInputOfTheSiteTemplateIsNoSignal(t *testing.T) {
	const o = "http://ci.test:8080"
	box := func(r *engine.MapEntry) {
		r.Params = []string{"q"}
		r.Forms = []engine.MapForm{{Method: "GET", Action: "/search", Fields: []string{"q"}}}
	}
	var rows []engine.MapEntry
	for i := 0; i < 8; i++ {
		rows = append(rows, urlRow(fmt.Sprintf("%s/view/page%d", o, i), "page", "visited", 200, box))
	}
	rows = append(rows,
		urlRow(o+"/find?q=apple", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"q"} }),
		urlRow(o+"/go?next=x", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"next", "q"} }),
	)
	got := build(rows...)
	for _, r := range got {
		if strings.Contains(r.Key, "/view/page") {
			t.Errorf("a page that only carries the template's search box ranks: %+v", r)
		}
	}
	if find(got, o+"/find?q=apple") == nil && find(got, o+"/find?q={v}") == nil {
		t.Errorf("the route with q in its own query is lost: %+v", got)
	}
	r := find(got, o+"/go?next=x")
	if r == nil || !has(r, "param-redirect") || has(r, "param-query") {
		t.Errorf("a route keeps its own names and not the template's: %+v", r)
	}
}
