package jscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// A key of a webpack module map and a case label name a path in the
// bundler's source tree, not a route of the app: no row, no hint, and a
// rejected string with its reason. A "./x?y=" written as a value stays.
func TestModuleMapKeysAreNotRoutes(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>App</title><script src="/static/main.entry.js"></script>`))
	})
	mux.HandleFunc("/static/main.entry.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var m={"./components/locale/zh_CN":0,"./components/locale/zh_TW":1,"./AdhocFilter":2,"./AdhocMetric":3};` +
			`function r(e){switch(e){case"./Alpha":return 4;case "./Beta":return 5}}` +
			`var t=a?"./TernA":"./TernB";var q="/?#";var go="./redirect?to=";`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	routes := map[string]bool{}
	rejected := map[string]string{}
	emit := func(o types.Observation) error {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case "url":
			routes[strings.TrimPrefix(p["url"].(string), srv.URL)] = true
		case "rejected":
			rejected[p["string"].(string)] = p["reason"].(string)
		}
		return nil
	}
	meta, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, emit)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"./components/locale/zh_CN", "./components/locale/zh_TW", "./AdhocFilter", "./AdhocMetric", "./Alpha", "./Beta"}
	for _, k := range keys {
		path := strings.TrimPrefix(k, ".")
		if routes[path] {
			t.Errorf("%s is a module id, not a route: %v", k, routes)
		}
		for _, h := range meta.NextHints {
			if strings.HasSuffix(h.Keys["url"], path) {
				t.Errorf("%s is requested as a hint", k)
			}
		}
		if rejected[k] != webextract.ReasonModuleKey {
			t.Errorf("%s: rejected as %q, want the module-key reason (%v)", k, rejected[k], rejected)
		}
	}
	for _, want := range []string{"/redirect", "/TernA", "/TernB"} {
		if !routes[want] {
			t.Errorf("%s is a route: %v", want, routes)
		}
	}
}
