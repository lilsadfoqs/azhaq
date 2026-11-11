package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// A page served under /web/ whose inline config builds the API base from
// window.location (ShowDoc's shape), and a script that uses it as its
// client's baseURL and in X + "/path".
func globalsApp(t *testing.T, bundle string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/web/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><title>Docs</title><script>
  window.Cfg = {
    // "server":'http://127.0.0.1/old/server/index.php?s=',
    server: window.location.protocol + '//' + window.location.host + window.location.pathname + '../server/index.php?s=',
    lang: 'en'
  }
</script><script src="static/app.js"></script>`))
		case r.URL.Path == "/web/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(bundle))
		case r.URL.Path == "/server/index.php" && strings.HasPrefix(r.URL.Query().Get("s"), "/api/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runGlobals(t *testing.T, srv *httptest.Server) (map[string]map[string]any, types.RunMeta) {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	rows := map[string]map[string]any{}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/web/"}}, func(o types.Observation) error {
		if o.Kind == "url" {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			rows[strings.TrimPrefix(p["url"].(string), srv.URL)] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows, meta
}

func TestRoutesJoinOntoABaseTheInlineConfigBuildsFromTheLocation(t *testing.T) {
	srv := globalsApp(t, `axios.defaults.baseURL=Cfg.server;`+
		`function a(){return axios.get("/api/common/homePageSetting")}`+
		`function b(d){return axios.post(Cfg.server+"/api/user/login",{username:d.u,password:d.p})}`)
	rows, meta := runGlobals(t, srv)
	get := "/server/index.php?s=/api/common/homePageSetting"
	row := rows[get]
	if row == nil || row["base"] != srv.URL+"/server/index.php?s=" {
		t.Fatalf("%s: want a call row naming its base, got %v (rows %v)", get, row, rowKeys(rows))
	}
	if ms, _ := row["methods"].([]any); len(ms) != 1 || ms[0] != "GET" {
		t.Errorf("%s: methods %v, want GET", get, row["methods"])
	}
	post := rows["/server/index.php?s=/api/user/login"]
	if ms, _ := post["methods"].([]any); post == nil || len(ms) != 1 || ms[0] != "POST" {
		t.Errorf("the POST built on the global has no row: %v (rows %v)", post, rowKeys(rows))
	}
	for _, bare := range []string{"/api/common/homePageSetting", "/api/user/login", "/server/index.php", "/server/index.php?s="} {
		if _, ok := rows[bare]; ok {
			t.Errorf("%s is listed, but the app asks it only under its base: %v", bare, rowKeys(rows))
		}
	}
	for _, h := range meta.NextHints {
		if u := strings.TrimPrefix(h.Keys["url"], srv.URL); u == "/api/common/homePageSetting" || strings.Contains(h.Keys["url"], "old/server") {
			t.Errorf("requested %s", u)
		}
	}
}

// ShowDoc's request helper and its URLs held as values: the helper joins
// its parameter onto the base and hands a config to axios, the app calls
// it as this.request(path, data, method), and a field holds a URL on the
// base. Each is listed under the base, none at the root.
func TestHelperAndValueURLsAreListedUnderTheInlineBase(t *testing.T) {
	srv := globalsApp(t, `axios.defaults.baseURL=Cfg.server;var u=axios;`+
		`var f=function(t,e){var i=arguments.length>2&&void 0!==arguments[2]?arguments[2]:"post",o=Cfg.server+t;`+
		`var l={url:o,method:i,data:new URLSearchParams(e),headers:{}};return new Promise(function(t,e){u(l)})};`+
		`Vue.prototype.request=f;`+
		`var page={data(){return{uploadUrl:Cfg.server+"/api/page/upload"}},methods:{`+
		`a(){this.request("/api/item/info",{item_id:1,keyword:2},"post",!1)},`+
		`b(){this.request("/api/user/allUser",{})},`+
		`c(){this.request("/api/item/list",{},"get")}}}`)
	rows, meta := runGlobals(t, srv)
	base := "/server/index.php?s="
	for route, method := range map[string]string{"/api/item/info": "POST", "/api/user/allUser": "POST", "/api/item/list": "GET"} {
		row := rows[base+route]
		ms, _ := row["methods"].([]any)
		if row == nil || len(ms) != 1 || ms[0] != method || row["base"] != srv.URL+base {
			t.Errorf("%s: want a %s row on the base, got %v", route, method, row)
		}
	}
	if body, _ := rows[base+"/api/item/info"]["body"].([]any); len(body) != 2 {
		t.Errorf("the body fields the caller sends: %v", rows[base+"/api/item/info"])
	}
	up := rows[base+"/api/page/upload"]
	if up == nil || up["via"] != "js" || up["methods"] != nil {
		t.Errorf("a URL held as a value is a row like the other strings, with no method: %v", up)
	}
	for _, bare := range []string{"/api/item/info", "/api/user/allUser", "/api/item/list", "/api/page/upload", "/server/index.php"} {
		if _, ok := rows[bare]; ok {
			t.Errorf("%s is listed at the root: %v", bare, rowKeys(rows))
		}
	}
	hinted := map[string]bool{}
	for _, h := range meta.NextHints {
		hinted[strings.TrimPrefix(h.Keys["url"], srv.URL)] = true
	}
	if !hinted[base+"/api/item/list"] || !hinted[base+"/api/page/upload"] || hinted["/api/page/upload"] {
		t.Errorf("hints: %v", hinted)
	}
}
