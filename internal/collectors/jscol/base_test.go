package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// baseApp is a single-page app whose client is given a base: a query-string
// dispatcher (server/index.php?s=) and an API prefix (/api/v2). Only the
// routes under the bases answer; the same paths at the root are 404, and
// every request is counted.
func baseApp(t *testing.T, bundle string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.RequestURI())
		mu.Unlock()
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><script src="/app.js"></script>`))
		case r.URL.Path == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(bundle))
		case r.URL.Path == "/server/index.php" && strings.HasPrefix(r.URL.Query().Get("s"), "/item/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":1}`))
		case strings.HasPrefix(r.URL.Path, "/api/v2/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":1}`))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), asked...) }
}

type baseRun struct {
	rows     map[string]map[string]any
	hints    []string
	rejected map[string]map[string]string
}

func runBase(t *testing.T, srv *httptest.Server) baseRun {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	out := baseRun{rows: map[string]map[string]any{}, rejected: map[string]map[string]string{}}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		switch o.Kind {
		case "url":
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			out.rows[strings.TrimPrefix(p["url"].(string), srv.URL)] = p
		case "rejected":
			var p map[string]string
			_ = json.Unmarshal(o.Payload, &p)
			out.rejected[p["string"]] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range meta.NextHints {
		out.hints = append(out.hints, strings.TrimPrefix(h.Keys["url"], srv.URL))
	}
	return out
}

func (r baseRun) hinted(p string) bool {
	for _, h := range r.hints {
		if h == p {
			return true
		}
	}
	return false
}

// A script whose client is given a base joins every route onto it: a
// query-string dispatcher keeps the route as its query, an API prefix is a
// path. The rows name the base, the routes are never asked at the root,
// and the paths as the script writes them are rejected strings, not rows.
func TestRoutesJoinOntoTheBaseTheScriptDeclares(t *testing.T) {
	srv, _ := baseApp(t, `var http=axios.create({baseURL:"server/index.php?s=",timeout:9e3});`+
		`var api=axios.create({baseURL:"/api/v2"});`+
		`function a(){return http.get("/item/list")}`+
		`function b(d){return http.post("/item/add",{name:d.name,qty:d.qty})}`+
		`function c(){return api.get("/orders/list")}`+
		`function d(id){return api.delete("/orders/"+id)}`)
	r := runBase(t, srv)

	item := "/server/index.php?s=/item/list"
	if row := r.rows[item]; row == nil || row["base"] != srv.URL+"/server/index.php?s=" || row["via"] != "js-call" {
		t.Fatalf("%s: want a call row naming its base, got %v (rows %v)", item, row, rowKeys(r.rows))
	}
	if row := r.rows["/server/index.php?s=/item/add"]; row == nil || len(row["methods"].([]any)) != 1 || row["methods"].([]any)[0] != "POST" {
		t.Errorf("the dispatcher's POST route has no row: %v", rowKeys(r.rows))
	}
	if row := r.rows["/api/v2/orders/list"]; row == nil || row["base"] != srv.URL+"/api/v2" {
		t.Errorf("/api/v2/orders/list: %v", row)
	}
	if row := r.rows["/api/v2/orders/{id}"]; row == nil || row["base"] != srv.URL+"/api/v2" {
		t.Errorf("/api/v2/orders/{id}: %v", row)
	}
	for _, bare := range []string{"/item/list", "/item/add", "/orders/list", "/orders/{id}", "/server/index.php"} {
		if _, ok := r.rows[bare]; ok {
			t.Errorf("%s is asked only under its base, not a found route: %v", bare, rowKeys(r.rows))
		}
		if r.hinted(bare) {
			t.Errorf("%s is requested at the root", bare)
		}
	}
	for _, want := range []string{item, "/api/v2/orders/list"} {
		if !r.hinted(want) {
			t.Errorf("%s is not requested: %v", want, r.hints)
		}
	}
	for _, bare := range []string{"/server/index.php", "/api/v2"} {
		if _, ok := r.rows[bare]; ok || r.hinted(bare) {
			t.Errorf("%s is the base the calls are built on, not a route", bare)
		}
	}
	for _, s := range []string{"/item/list", "/item/add", "/orders/list"} {
		if r.rejected[s]["reason"] != webextract.ReasonBased {
			t.Errorf("%s: rejected as %q, want the base reason (%v)", s, r.rejected[s]["reason"], r.rejected)
		}
	}
}

// A route the script asks both under its base and at the root is a route
// at the root as well; a client the script gives no base is left alone; an
// absolute URL keeps its host.
func TestBaseDoesNotHideWhatIsAskedAtTheRoot(t *testing.T) {
	srv, _ := baseApp(t, `var api=axios.create({baseURL:"/api/v2"});`+
		`function a(){return api.get("/orders/list")}`+
		`function b(){return fetch("/orders/list")}`+
		`function c(){return fetch("/health")}`+
		`function d(){return axios.get("/ping")}`)
	r := runBase(t, srv)
	if r.rows["/api/v2/orders/list"] == nil {
		t.Errorf("the based call has no row: %v", rowKeys(r.rows))
	}
	for _, p := range []string{"/orders/list", "/health", "/ping"} {
		if r.rows[p] == nil {
			t.Errorf("%s is asked at the root and has no row: %v", p, rowKeys(r.rows))
		}
	}
	if row := r.rows["/orders/list"]; row != nil && row["base"] != nil {
		t.Errorf("a route asked at the root names a base: %v", row)
	}
}

func rowKeys(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
