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

// The keys of a bundle's module table are module ids, not routes: a string
// that is only the key of an object whose value is a function is not
// requested and is counted as rejected. One that is also a call argument, a
// link or part of a URL elsewhere in the script stays a route, and the
// routes the bundle names are the same as before.
func TestModuleTableKeysAreNotRequested(t *testing.T) {
	fetch.Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><title>App</title><script src="/main.js"></script>`))
	})
	mux.HandleFunc("/main.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`(window.webpackJsonp=window.webpackJsonp||[]).push([[1],{` +
			`"21U":function(t,e,n){"use strict";n.r(e)},` +
			`"/HAE":function(t,e,n){var a=n("/KAi");return a.get("/rest/products/search")},` +
			`"/KAi":function(t,e,n){},` +
			`"/Mod2":(t,e,n)=>{n.r(e)},` +
			`"/Mod3":async function(){},` +
			`"/Mod4"(t,e){},` +
			`"/Both":function(t,e,n){},` +
			`"/rest/admin/application-version":function(){return 1},` +
			`"+HcW":function(t,e){}}]);` +
			`fetch("/Both");var u="/api/Users";var l="/pages/"+id;`))
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
	asked := map[string]bool{}
	for p := range routes {
		asked[p] = true
	}
	for _, h := range meta.NextHints {
		asked[strings.TrimPrefix(h.Keys["url"], srv.URL)] = true
	}
	// "/KAi" is a key and also a call argument, "/Both" a key and a fetch.
	for _, k := range []string{"/HAE", "/Mod2", "/Mod3", "/Mod4", "/rest/admin/application-version"} {
		if asked[k] {
			t.Errorf("%s is a module id, not a route: asked %v", k, asked)
		}
		if rejected[k] != webextract.ReasonModuleKey {
			t.Errorf("%s: rejected as %q, want the module-key reason (%v)", k, rejected[k], rejected)
		}
	}
	for _, k := range []string{"/KAi", "/Both", "/rest/products/search", "/api/Users"} {
		if !asked[k] {
			t.Errorf("%s names a route: asked %v", k, asked)
		}
	}
	if _, ok := rejected["/KAi"]; ok {
		t.Errorf("/KAi is a route elsewhere and is not rejected: %v", rejected)
	}
}
