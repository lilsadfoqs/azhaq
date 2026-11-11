package webextract

import (
	"net/url"
	"testing"
)

func TestPageGlobalsFromLocation(t *testing.T) {
	page, _ := url.Parse("http://app.test:8080/web/")
	cases := []struct {
		name, script string
		want         map[string]string
	}{
		{"object", `window.Cfg = {
			// "server": 'http://127.0.0.1/old/index.php?s=',
			server: window.location.protocol + '//' + window.location.host + window.location.pathname + '../server/index.php?s=',
			lang: 'zh-cn'
		}`, map[string]string{"Cfg.server": "http://app.test:8080/server/index.php?s="}},
		{"origin", `window.API_BASE = location.origin + '/api'`, map[string]string{"API_BASE": "http://app.test:8080/api"}},
		{"var", `var apiRoot = document.location.protocol + "//" + document.location.hostname + ":" + document.location.port + "/v1";`,
			map[string]string{"apiRoot": "http://app.test:8080/v1"}},
		{"template", "const R = `${location.origin}/x`", map[string]string{"R": "http://app.test:8080/x"}},
		{"earlier global", `var a = location.origin; var b = a + "/api"`, map[string]string{"a": "http://app.test:8080", "b": "http://app.test:8080/api"}},
		{"no location", `window.X = "/api"; var y = "http://a.test"`, nil},
		{"unknown part", `window.X = location.origin + "/" + getTenant()`, nil},
		{"unknown property", `window.X = location.search + "/a"`, nil},
		{"commented out", `// window.X = location.origin + "/api"
/* var Y = location.origin */`, nil},
		{"inside a function", `function f(){ var Z = location.origin + "/api" }`, nil},
		{"window inside a function", `(function(){ window.W = location.origin + "/api" })()`, map[string]string{"W": "http://app.test:8080/api"}},
	}
	for _, c := range cases {
		got := PageGlobals([]string{c.script}, page)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: %s is %q, want %q", c.name, k, got[k], v)
			}
		}
	}
}

func TestPageGlobalsDefaultPort(t *testing.T) {
	page, _ := url.Parse("https://app.test:443/a/b.html")
	g := PageGlobals([]string{`var u = location.host + location.pathname + "|" + location.origin`}, page)
	if want := "app.test/a/b.html|https://app.test"; g["u"] != want {
		t.Errorf("u is %q, want %q", g["u"], want)
	}
}

// A global the page sets from its location is a base: a client's
// baseURL, or the start of a URL, joined to the routes by text.
func TestCallsOnPageGlobals(t *testing.T) {
	page, _ := url.Parse("http://app.test/web/")
	g := PageGlobals([]string{`window.Cfg = {server: location.protocol + '//' + location.host + location.pathname + '../server/index.php?s='}`}, page)
	app := `axios.defaults.baseURL=Cfg.server;` +
		`function a(){return axios.get("/item/list")}` +
		`function b(){return axios.post(Cfg.server+"/api/login",{user:1})}` +
		`function c(){return fetch(Cfg.server+"/api/page/save",{method:"POST"})}`
	want := map[string]string{
		"GET http://app.test/server/index.php?s=/item/list":      "/item/list",
		"POST http://app.test/server/index.php?s=/api/login":     "/api/login",
		"POST http://app.test/server/index.php?s=/api/page/save": "/api/page/save",
	}
	got := CallsWith(app, g)
	if len(got) != len(want) {
		t.Fatalf("%+v, want %v", got, want)
	}
	for _, c := range got {
		route, ok := want[c.Method+" "+c.Path]
		if !ok || c.Route != route || c.Base != "http://app.test/server/index.php?s=" {
			t.Errorf("%s %s (route %q, base %q), want one of %v", c.Method, c.Path, c.Route, c.Base, want)
		}
	}
	// Without the page's globals the base is not known: no guessed root path.
	for _, c := range Calls(app) {
		if c.Base != "" {
			t.Errorf("without globals: %+v", c)
		}
	}
}

func TestPageGlobalsNotForLocals(t *testing.T) {
	page, _ := url.Parse("http://app.test/")
	g := PageGlobals([]string{`var apiRoot = location.origin + "/api"; var ab = location.origin + "/zz"`}, page)
	// a function's own parameter, and a minified two-letter local, are not the global
	app := `function get(apiRoot){return fetch(apiRoot+"/x")}function k(ab){return fetch(ab+"/y")}`
	for _, c := range CallsWith(app, g) {
		if c.Base != "" || c.Path == "http://app.test/api/x" || c.Path == "http://app.test/zz/y" {
			t.Errorf("a local took the global: %+v", c)
		}
	}
}

// ShowDoc's helper: a function that joins its parameter onto the page's
// base in a local and hands a config object to an alias of axios; the
// app calls it as this.request(path, data, method).
const helperApp = `axios.defaults.baseURL=Cfg.server;var u=axios;` +
	`var f=function(t,e){var i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:"post",o=Cfg.server+t,s=1;` +
	`var l={url:o,method:i,data:new URLSearchParams(e),headers:{}};return new Promise(function(t,e){u(l)})};` +
	`Vue.prototype.request=f;` +
	`var page={data(){return{uploadUrl:Cfg.server+"/api/page/upload"}},methods:{` +
	`a(){this.request("/api/item/info",{item_id:1,keyword:2},"post",!1)},` +
	`b(){this.request("/api/user/allUser",{})},` +
	`c(){this.request("/api/item/list",{},"get")},` +
	`d(){var x=Cfg.server+"/api/ScriptCron/run"}}}`

func TestCallsThroughAHelperOnAPageGlobal(t *testing.T) {
	page, _ := url.Parse("http://app.test/web/")
	g := PageGlobals([]string{`window.Cfg = {server: location.protocol + '//' + location.host + location.pathname + '../server/index.php?s='}`}, page)
	base := "http://app.test/server/index.php?s="
	got := map[string]Call{}
	for _, c := range MergeCalls(CallsWith(helperApp, g)) {
		got[c.Method+" "+c.Path] = c
	}
	for _, want := range []string{
		"POST " + base + "/api/item/info", "POST " + base + "/api/user/allUser", "GET " + base + "/api/item/list",
		" " + base + "/api/page/upload", " " + base + "/api/ScriptCron/run",
	} {
		c, ok := got[want]
		if !ok || c.Base != base {
			t.Errorf("%q: %+v (calls %v)", want, c, got)
		}
	}
	if c := got["POST "+base+"/api/item/info"]; len(c.Body) != 2 || c.Body[0] != "item_id" || c.Body[1] != "keyword" {
		t.Errorf("the body fields the caller sends: %v", c.Body)
	}
	if !got[" "+base+"/api/page/upload"].Value {
		t.Errorf("a URL held as a value is a value: %+v", got)
	}
	for k, c := range got {
		if c.Path == "http://app.test/server/index.php" || c.Base == "" {
			t.Errorf("%s: no route on the base: %+v", k, c)
		}
	}
	// With no page globals the base is unknown: nothing is joined onto a guess.
	for _, c := range Calls(helperApp) {
		if c.Base != "" || c.Value {
			t.Errorf("without globals: %+v", c)
		}
	}
}

// A helper whose name is shared by another function is not followed, and
// a URL on the base with nothing after it is no route.
func TestHelperNeedsOneNameAndARoute(t *testing.T) {
	page, _ := url.Parse("http://app.test/")
	g := PageGlobals([]string{`var Api = location.origin + "/server/index.php?s="`}, page)
	two := helperApp + `;var q=function(t){return 1};Other.prototype.request=function(t){return fetch("/x"+t)}`
	for _, c := range CallsWith(two, g) {
		if c.Method == "POST" && c.Base != "" {
			t.Errorf("two functions are stored as request: %+v", c)
		}
	}
}
