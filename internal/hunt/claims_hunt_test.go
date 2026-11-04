package hunt

import (
	"fmt"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
)

// A route a script or a description gives methods for counts in full though
// nothing asked it; one that is only named, with no method, weighs half.
func TestARouteWithMethodsCountsInFullAndANamedOneWeighsHalf(t *testing.T) {
	const o = "http://t.test"
	asked := build(urlRow(o+"/admin", "page", "visited", 200, nil))
	given := build(urlRow(o+"/admin", "page", "hint", 0, func(r *engine.MapEntry) { r.Methods = []string{"GET"} }))
	named := build(urlRow(o+"/admin", "page", "hint", 0, nil))
	if len(asked) != 1 || len(given) != 1 || len(named) != 1 {
		t.Fatalf("rows %d %d %d", len(asked), len(given), len(named))
	}
	if asked[0].Score != 40 || given[0].Score != 40 || named[0].Score != 20 {
		t.Errorf("an answered route scores %d, one a script gives methods for %d, a named one %d: want 40, 40 and 20", asked[0].Score, given[0].Score, named[0].Score)
	}
}

// A route whose GET answered 405, 400, 415 or 422 counts in full: the server
// has it, it only refused this request. A 404 does not.
func TestAGetAnswered405400415Or422CountsInFull(t *testing.T) {
	const o = "http://t.test"
	for _, st := range []int{405, 400, 415, 422} {
		rows := build(urlRow(o+"/admin", "api", "visited", st, nil))
		if len(rows) != 1 || rows[0].Score != 40 {
			t.Errorf("GET answered %d: %+v, want the admin word in full (40)", st, rows)
		}
	}
	if rows := build(urlRow(o+"/admin", "api", "visited", 404, nil)); len(rows) != 0 {
		t.Errorf("a 404 is no row: %+v", rows)
	}
}

// A route only a script names and whose GET answered 404 or 410 keeps the
// signals the script gives it, and comes after every row the server confirmed
// (200, 401, 403, 405 and other 4xx, 5xx), whatever the scores; with nothing
// else known of it the row is left out.
func TestAnUnconfirmedNamedRouteKeepsItsScriptSignalsAndComesAfterEveryConfirmedRow(t *testing.T) {
	const o = "http://t.test"
	var rows []engine.MapEntry
	for _, st := range []int{200, 401, 403, 405, 409, 500} {
		st := st
		rows = append(rows, urlRow(fmt.Sprintf("%s/seen%d", o, st), "api", "visited", st, func(r *engine.MapEntry) { r.Params = []string{fmt.Sprint("zz", st)} }))
	}
	for _, st := range []int{404, 410} {
		rows = append(rows, urlRow(fmt.Sprintf("%s/api/items%d", o, st), "api", "hint", st, func(r *engine.MapEntry) {
			r.Methods, r.Body = []string{"POST"}, []string{"name", "price"}
			r.Ops = []engine.Op{{Method: "POST", Body: r.Body, Source: "js-call"}}
		}))
	}
	rows = append(rows, urlRow(o+"/api/ghost", "api", "hint", 404, nil))
	got := build(rows...)
	if find(got, o+"/api/ghost") != nil {
		t.Errorf("a route nothing but a script's name is known of is a row: %+v", find(got, o+"/api/ghost"))
	}
	var lastConfirmed int
	var weakest = 1 << 30
	for _, st := range []int{200, 401, 403, 405, 409, 500} {
		r := find(got, fmt.Sprintf("%s/seen%d", o, st))
		if r == nil {
			t.Fatalf("the route answered %d is no row: %+v", st, got)
		}
		lastConfirmed = max(lastConfirmed, r.Rank)
		weakest = min(weakest, r.Score)
	}
	for _, st := range []int{404, 410} {
		r := find(got, fmt.Sprintf("%s/api/items%d", o, st))
		if r == nil {
			t.Fatalf("the named route answered %d is no row: %+v", st, got)
		}
		if !has(r, "input") || !has(r, "unauth-write") || !has(r, "unconfirmed") {
			t.Errorf("GET %d: its signals %+v: want the fields it sends and a write without credentials", st, r.Reasons)
		}
		if r.Score <= weakest {
			t.Fatalf("GET %d: it scores %d, not above the weakest confirmed row (%d): the test would show nothing", st, r.Score, weakest)
		}
		if r.Rank <= lastConfirmed {
			t.Errorf("GET %d: rank %d, a confirmed row has rank %d: it comes after every one whatever the score", st, r.Rank, lastConfirmed)
		}
	}
}

// The site's template: at least 5 of the origin's fetched pages carry an
// input name, and at least 40% of them; with fewer, or a smaller share, each
// page keeps the input as its own.
func TestAnInputIsTheSitesTemplateAtFivePagesAndFortyPercent(t *testing.T) {
	const o = "http://t.test"
	for _, tc := range []struct {
		carry, pages int
		template     bool
	}{
		{4, 4, false},   // all of them, but fewer than 5
		{5, 12, true},   // 5 and 41.7%
		{5, 13, false},  // 5 and 38.5%
		{6, 15, true},   // exactly 40%
		{6, 16, false},  // 37.5%
		{40, 100, true}, // exactly 40%
	} {
		var rows []engine.MapEntry
		for i := 0; i < tc.pages; i++ {
			i := i
			rows = append(rows, urlRow(fmt.Sprintf("%s/p%03d", o, i), "page", "visited", 200, func(r *engine.MapEntry) {
				if i < tc.carry {
					r.Params = []string{"zz"}
					r.Forms = []engine.MapForm{{Method: "GET", Action: "/s", Fields: []string{"zz"}}}
				}
			}))
		}
		got := build(rows...)
		var tmpl bool
		for _, r := range got {
			tmpl = tmpl || r.Template != nil
		}
		if tmpl != tc.template || (tc.template && len(got) != 1) || (!tc.template && len(got) != tc.carry) {
			t.Errorf("%d of %d pages carry it: template %v, %d rows, want template %v and %d rows", tc.carry, tc.pages, tmpl, len(got), tc.template, map[bool]int{true: 1, false: tc.carry}[tc.template])
		}
	}
}

// A sign-in, sign-up or password reset page that is not an API route weighs
// 10, and a data word beside it adds at most 10; an API route with the same
// words keeps 45.
func TestASignInPageWeighsTenAndADataWordAddsAtMostTen(t *testing.T) {
	const o = "http://t.test"
	score := func(path, role string) int {
		rows := build(urlRow(o+path, role, "visited", 200, nil))
		if len(rows) != 1 {
			t.Fatalf("%s: %d rows", path, len(rows))
		}
		return rows[0].Score
	}
	for _, p := range []string{"/login", "/signin", "/signon", "/logon", "/reset", "/forgot", "/recover", "/register", "/signup"} {
		if got := score(p, "page"); got != 10 {
			t.Errorf("%s weighs %d, want 10", p, got)
		}
	}
	for _, p := range []string{"/user/login", "/reset_password", "/account/register"} {
		if got := score(p, "page"); got < 10 || got > 20 {
			t.Errorf("%s weighs %d, want 10 and at most 10 for the data word", p, got)
		}
	}
	for _, p := range []string{"/api/login", "/auth", "/oauth", "/sso", "/saml", "/token", "/mfa", "/2fa"} {
		if got := score(p, "api"); got != 45 {
			t.Errorf("%s as an API route weighs %d, want 45", p, got)
		}
	}
	for _, p := range []string{"/auth", "/oauth", "/sso", "/saml", "/token", "/mfa", "/2fa"} {
		if got := score(p, "page"); got != 45 {
			t.Errorf("%s on a page weighs %d, want 45", p, got)
		}
	}
}
