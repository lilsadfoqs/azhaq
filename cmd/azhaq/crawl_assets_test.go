package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A page that loads two scripts, a library script, two stylesheets, an image
// and an icon, and a script that imports a chunk.
func assetsSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js := func(body string) {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, body)
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel="stylesheet" href="/styles.css"><link rel="stylesheet" href="/assets/fa/css/font-awesome.min.css"><script src="/assets/jquery-3.2.1.min.js"></script><link rel="icon" href="/favicon.ico"><script src="/main.js"></script><script src="/polyfills.js"></script></head><body><img src="/logo.png"><a href="/about">about</a></body></html>`)
		case "/main.js":
			js(`import("./chunk-abc.js").then(function (m) { m.go(); });`)
		case "/polyfills.js":
			js(`window.polyfilled = true;`)
		case "/chunk-abc.js":
			js(`export function go() {}`)
		case "/assets/jquery-3.2.1.min.js":
			js(`window.jQuery = {};`)
		case "/styles.css", "/assets/fa/css/font-awesome.min.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `body { margin: 0 }`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>about</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func crawlLines(t *testing.T, srv *httptest.Server, args ...string) map[string]bool {
	t.Helper()
	out, _, err := captureBoth(t, func() error {
		return cmdCrawl(append([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", filepath.Join(t.TempDir(), "w.db")}, args...))
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		lines[strings.TrimPrefix(l, srv.URL)] = true
	}
	return lines
}

// crawl lists what the pages it reads load, as katana does: the scripts and
// stylesheets (a library script and a stylesheet no crawl step requests too)
// by default, and the images, fonts and media with -assets. The rows no
// request asked are marked linked.
func TestCrawlListsScriptsAndStylesByDefault(t *testing.T) {
	srv := assetsSite(t)
	const jq, fa = "/assets/jquery-3.2.1.min.js", "/assets/fa/css/font-awesome.min.css"
	lines := crawlLines(t, srv)
	for _, want := range []string{"/", "/about", "/main.js", "/polyfills.js", "/chunk-abc.js", "/styles.css", jq, fa} {
		if !lines[want] {
			t.Errorf("crawl does not list %s: %v", want, lines)
		}
	}
	for _, not := range []string{"/logo.png", "/favicon.ico"} {
		if lines[not] {
			t.Errorf("crawl lists %s without -assets", not)
		}
	}
	all := crawlLines(t, srv, "-assets")
	for _, want := range []string{"/main.js", "/styles.css", jq, fa, "/logo.png", "/favicon.ico"} {
		if !all[want] {
			t.Errorf("crawl -assets does not list %s: %v", want, all)
		}
	}
	rows := urlRows(t, func() string {
		out, _, _ := captureBoth(t, func() error {
			return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
		})
		return out
	}())
	for want, class := range map[string]string{"/main.js": "observed", "/chunk-abc.js": "observed", "/styles.css": "observed", jq: "linked", fa: "observed"} {
		if rows[srv.URL+want] == nil {
			t.Errorf("crawl -json has no row for %s", want)
		} else if rows[srv.URL+want]["class"] != class {
			t.Errorf("crawl -json marks %s %v, want %s", want, rows[srv.URL+want]["class"], class)
		}
	}
	if rows[srv.URL+"/logo.png"] != nil {
		t.Error("crawl -json lists an image without -assets")
	}
}

// The stylesheets a page loads are requested, as katana does, and listed as
// observed rows: the URLs they name are read, an @import is requested too,
// and the images and fonts stay unrequested and linked.
func TestCrawlRequestsTheStylesheetsAPageLoads(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel="stylesheet" href="/css/site.css"><link rel="icon" href="/favicon.ico"></head><body><img src="/logo.png"></body></html>`)
		case "/css/site.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `@import url("theme.css"); body { background: url(../img/bg.png) } @font-face { src: url('/fonts/f.woff2') } /* a { background: url(/gone.png) } */`)
		case "/css/theme.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `h1 { background: url(/img/h1.gif) }`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	rows := urlRows(t, func() string {
		out, _, _ := captureBoth(t, func() error {
			return cmdCrawl([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-json", "-assets", "-db", filepath.Join(t.TempDir(), "w.db")})
		})
		return out
	}())
	for want, class := range map[string]string{"/css/site.css": "observed", "/css/theme.css": "observed", "/img/bg.png": "linked", "/fonts/f.woff2": "linked", "/img/h1.gif": "linked", "/logo.png": "linked"} {
		if rows[srv.URL+want] == nil {
			t.Errorf("crawl has no row for %s: %v", want, rows)
		} else if rows[srv.URL+want]["class"] != class {
			t.Errorf("%s is %v, want %s", want, rows[srv.URL+want]["class"], class)
		}
	}
	if rows[srv.URL+"/gone.png"] != nil {
		t.Error("a url() in a comment is listed")
	}
	mu.Lock()
	defer mu.Unlock()
	if asked["/css/site.css"] != 1 || asked["/css/theme.css"] != 1 {
		t.Errorf("the stylesheets are each requested once: %v", asked)
	}
	for _, p := range []string{"/img/bg.png", "/fonts/f.woff2", "/img/h1.gif", "/logo.png", "/favicon.ico"} {
		if asked[p] != 0 {
			t.Errorf("%s was requested: images, fonts and media are not", p)
		}
	}
}
