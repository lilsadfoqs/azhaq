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

// The search box every page of a site carries is one row of its own, on the
// page it was first seen on, marked as the site's template; the pages that
// only carry it have no row, and the route that takes the name in its own
// query keeps it.
func TestInputOfTheSiteTemplateIsOneRow(t *testing.T) {
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
		urlRow(o+"/go?next=x", "page", "visited", 200, func(r *engine.MapEntry) { r.Params = []string{"next"} }),
	)
	got := build(rows...)
	var tmpl *Row
	for i := range got {
		if got[i].Template != nil {
			if tmpl != nil {
				t.Errorf("more than one template row: %+v", got)
			}
			tmpl = &got[i]
		} else if strings.Contains(got[i].Key, "/view/page") {
			t.Errorf("a page that only carries the template's search box ranks: %+v", got[i])
		}
	}
	if tmpl == nil || tmpl.Template.Input != "q" || tmpl.Template.Pages != 8 || tmpl.Template.Of != 10 || tmpl.Key != o+"/view/page0" ||
		!has(tmpl, "param-query") || !strings.Contains(tmpl.Reasons[0].Detail, "input q on 8 of 10 pages of "+o+" (the site's template)") {
		t.Fatalf("the template row: %+v", tmpl)
	}
	if find(got, o+"/find?q=apple") == nil && find(got, o+"/find?q={v}") == nil {
		t.Errorf("the route with q in its own query is lost: %+v", got)
	}
	if r := find(got, o+"/go?next=x"); r == nil || !has(r, "param-redirect") || has(r, "param-query") {
		t.Errorf("a route keeps its own names and not the template's: %+v", r)
	}
}

// The v0.12 hunter's case: a search box on 312 of an origin's 340 pages was
// 77 of the top 100 rows. It is one row, below a real signal.
func TestSearchBoxOnMostPagesIsOneRowBelowARealSignal(t *testing.T) {
	const o = "http://ci.test:8080"
	var rows []engine.MapEntry
	for i := 0; i < 340; i++ {
		i := i
		rows = append(rows, urlRow(fmt.Sprintf("%s/job/p%03d", o, i), "page", "visited", 200, func(r *engine.MapEntry) {
			if i < 312 {
				r.Params = []string{"q"}
				r.Forms = []engine.MapForm{{Method: "GET", Action: "/search", Fields: []string{"q"}}}
			}
		}))
	}
	rows = append(rows, urlRow(o+"/backup.sql", "page", "visited", 200, nil))
	got := build(rows...)
	if len(got) != 2 {
		t.Fatalf("want the template row and the real signal, got %d rows: %+v", len(got), got[:min(len(got), 3)])
	}
	if got[0].Key != o+"/backup.sql" || got[1].Template == nil || got[1].Template.Pages != 312 || got[1].Template.Of != 341 {
		t.Errorf("a real signal ranks above the template input: %+v", got)
	}
	if !strings.Contains(got[1].Reasons[0].Detail, "input q on 312 of 341 pages") {
		t.Errorf("detail %q", got[1].Reasons[0].Detail)
	}
}
