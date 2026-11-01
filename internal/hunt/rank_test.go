package hunt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

const shop = "http://shop.test"

// The routes a tester starts with, as a Juice Shop map shows them: sign-in,
// a search, an XML upload, and a route whose plain request failed for lack
// of its input.
func shopRows() []engine.MapEntry {
	post := func(body ...string) func(*engine.MapEntry) {
		return func(r *engine.MapEntry) {
			r.Methods = []string{"POST"}
			r.Body = body
			r.Ops = []engine.Op{{Method: "POST", Body: body, Source: "js-call"}}
		}
	}
	return []engine.MapEntry{
		urlRow(shop+"/rest/user/login", "api", "hint", 0, post("email", "password")),
		urlRow(shop+"/b2b/v2/orders", "api", "hint", 0, func(r *engine.MapEntry) {
			r.Methods = []string{"POST"}
			r.Ops = []engine.Op{{Method: "POST", BodyType: "application/xml", Source: "openapi"}}
		}),
		urlRow(shop+"/rest/products/search", "api", "visited", 200, func(r *engine.MapEntry) {
			r.Methods, r.Params = []string{"GET"}, []string{"q"}
			r.Ops = []engine.Op{{Method: "GET", Query: []string{"q"}, Source: "js-call"}}
		}),
		urlRow(shop+"/rest/user/security-question", "api", "visited", 500, func(r *engine.MapEntry) {
			r.Title, r.Methods, r.Params, r.Answer = "Error", []string{"GET"}, []string{"email"}, "500 without input"
			r.Ops = []engine.Op{{Method: "GET", Query: []string{"email"}, Source: "js-call"}}
		}),
	}
}

func scores(rows []Row) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		out[strings.TrimPrefix(r.Key, shop)] = r.Score
	}
	return out
}

func TestGenericServerErrorRanksBelowWhatTakesInput(t *testing.T) {
	rows := build(shopRows()...)
	sc := scores(rows)
	sq := sc["/rest/user/security-question"]
	for _, k := range []string{"/rest/user/login", "/b2b/v2/orders", "/rest/products/search"} {
		if sc[k] <= sq {
			t.Errorf("%s scores %d, not above the 500 without input (%d): %v", k, sc[k], sq, sc)
		}
	}
	if rows[len(rows)-1].Key != shop+"/rest/user/security-question" {
		t.Errorf("a 500 to a request without its input ranks last of these four: %+v", rows)
	}
	sqRow := find(rows, shop+"/rest/user/security-question")
	var detail string
	for _, x := range sqRow.Reasons {
		if x.Signal == "server-error" {
			detail = x.Detail
		}
	}
	if !strings.Contains(detail, "without the input it takes (email)") {
		t.Errorf("reasons %+v", sqRow.Reasons)
	}
	for k, sig := range map[string]string{"/rest/user/login": "path-auth", "/rest/products/search": "path-search", "/b2b/v2/orders": "xml", "/rest/user/security-question": "input"} {
		if !has(find(rows, shop+k), sig) {
			t.Errorf("%s has no %s signal: %+v", k, sig, find(rows, shop+k))
		}
	}
}

// What corroborates a 5xx: SQL error text, a debug page, a stack trace, a
// parameter that came back, another role's answer.
func TestServerErrorNeedsCorroboration(t *testing.T) {
	row := func(path string) engine.MapEntry {
		return urlRow(shop+path, "api", "visited", 500, func(r *engine.MapEntry) { r.Title = "Error" })
	}
	text := func(path, kind, sample string) types.StoredObservation {
		payload, _ := json.Marshal(map[string]any{"url": shop + path, "status": 500, "error_text": kind, "error_sample": sample})
		return types.StoredObservation{EntityID: shop + path, Observation: types.Observation{Collector: "azhaq-http", Kind: "application", Payload: payload}}
	}
	reflected, _ := json.Marshal(map[string]any{"url": shop + "/r/echo", "params": []string{"q"}, "why": map[string]string{"q": "reflected"}})
	in := Input{DB: "w.db", Now: now, Since: 168 * 3600e9,
		Rows: []engine.MapEntry{row("/r/plain"), row("/r/one"), row("/r/two"), row("/r/three"), row("/r/echo")},
		Obs: []types.StoredObservation{
			text("/r/one", "sql", `SQLITE_ERROR: near "'": syntax error`),
			text("/r/two", "debug", "Werkzeug Debugger"),
			text("/r/three", "stack", "at Object.handler (/app/x.js:1:2)"),
			{EntityID: "x", Observation: types.Observation{Collector: "azhaq-params", Kind: "params", Payload: reflected}},
		},
	}
	sc := scores(Build(in))
	sql, debug, stack, echo, plain := sc["/r/one"], sc["/r/two"], sc["/r/three"], sc["/r/echo"], sc["/r/plain"]
	if !(sql > debug && debug > echo && echo > stack && stack > plain) {
		t.Errorf("sql > debug > reflected > stack > plain expected: %v", sc)
	}
	if plain != weights["server-error"] || sql != serverErrorSQL {
		t.Errorf("weights %v", sc)
	}
}

func TestServerErrorFlippedByARole(t *testing.T) {
	rows := []RoleRow{{URL: shop + "/rest/basket/mine", Verdict: "status differs", Status: map[string]int{"anon": 500, "user": 200}}}
	got := Build(Input{Roles: rows, Now: now})
	if len(got) != 1 || !has(&got[0], "server-error") || got[0].Score != serverErrorFlip ||
		!strings.Contains(got[0].Reasons[0].Detail, "500 for anon, 200 for user") {
		t.Fatalf("%+v", got)
	}
	same := []RoleRow{{URL: shop + "/rest/x", Verdict: "status differs", Status: map[string]int{"anon": 401, "user": 200}}}
	if got := Build(Input{Roles: same, Now: now}); len(got) != 0 {
		t.Errorf("a refusal for one role is no server error: %+v", got)
	}
}

func TestCrossRoleNextNamesTheRolesDirectory(t *testing.T) {
	rows := []RoleRow{
		{URL: shop + "/rest/basket/mine", Verdict: "reads another role's object", Confidence: "proved", Dir: "/work/azhaq-roles-20261031-101500"},
		{URL: shop + "/rest/orders/mine", Verdict: "reads another role's object", Confidence: "proved"},
	}
	got := Build(Input{Roles: rows, Now: now})
	next := map[string]string{}
	for _, r := range got {
		next[strings.TrimPrefix(r.Key, shop)] = r.Next
	}
	if want := "azhaq roles show -dir /work/azhaq-roles-20261031-101500 " + shop + "/rest/basket/mine"; next["/rest/basket/mine"] != want {
		t.Errorf("next %q, want %q", next["/rest/basket/mine"], want)
	}
	if n := next["/rest/orders/mine"]; strings.Contains(n, "DIR") || !strings.HasPrefix(n, "azhaq show -db ") {
		t.Errorf("a row whose roles directory is not known has no placeholder: %q", n)
	}
}

// A script names two routes with POST; the server answers 405 to a GET of
// one (it is there) and 404 to the other (nothing shows it is).
func TestNamedRouteThatAnswered404RanksBelowOneTheServerConfirmed(t *testing.T) {
	post := func(r *engine.MapEntry) {
		r.Methods, r.Body = []string{"POST"}, []string{"password", "username"}
		r.Ops = []engine.Op{{Method: "POST", Body: r.Body, Source: "js-call"}}
	}
	rows := build(
		urlRow(shop+"/api/user/login", "api", "visited", 405, post),
		urlRow(shop+"/api/user/register", "api", "hint", 404, post),
		urlRow(shop+"/api/orders/{id}", "api", "hint", 404, func(r *engine.MapEntry) { r.Methods = []string{"GET"} }),
		urlRow(shop+"/config.bak", "page", "hint", 404, func(r *engine.MapEntry) { r.Methods = []string{"GET"} }),
	)
	login, reg := find(rows, shop+"/api/user/login"), find(rows, shop+"/api/user/register")
	if login == nil || reg == nil {
		t.Fatalf("rows: %+v", rows)
	}
	if login.Rank >= reg.Rank {
		t.Errorf("405 route ranks %d, 404 route %d: %+v", login.Rank, reg.Rank, rows)
	}
	if !has(login, "path-auth") || !has(login, "path-data") {
		t.Errorf("a route the server confirmed keeps its path words: %+v", login)
	}
	if has(reg, "path-auth") || has(reg, "path-data") {
		t.Errorf("path words add nothing when only a script names the route: %+v", reg)
	}
	var why string
	for _, x := range reg.Reasons {
		if x.Signal == "unconfirmed" {
			why = x.Detail
		}
		if strings.Contains(x.Detail, "answers 404") {
			t.Errorf("a 404 is no reason for a score: %+v", x)
		}
	}
	if why != "named by a script, not confirmed: GET 404" {
		t.Errorf("reason = %q", why)
	}
	if has(find(rows, shop+"/config.bak"), "exposed-file") {
		t.Errorf("a file name a script gives, answered 404, is not an exposed file: %+v", rows)
	}
	// Even a 404 route with a heavier score sorts after the confirmed ones.
	if o := find(rows, shop+"/api/orders/{id}"); o != nil && o.Rank < login.Rank {
		t.Errorf("an unconfirmed route outranks a confirmed one: %+v", rows)
	}
}
