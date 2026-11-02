package contract

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Site is a small web app on 127.0.0.1: pages that link to each other, a
// script that names API routes, a form, directories a wordlist finds and
// a body that is the same for every missing path unless it is not given.
type Site struct {
	*httptest.Server
	Wire *Wire // what the origin itself saw

	mu    sync.Mutex
	delay time.Duration
	// Status overrides the answer for a path, 0 for none.
	status map[string]int
}

const siteIndex = `<!doctype html><html><head><title>Lab Shop</title>
<link rel="stylesheet" href="/static/site.css"></head><body>
<a href="/about">about</a> <a href="/products?id=1">one</a> <a href="/products?id=2">two</a>
<a href="/products?id=2">two again</a> <a href="/admin/">admin</a> <a href="/old">old</a>
<img src="/static/logo.png">
<form action="/search" method="get"><input name="q"></form>
<form action="/contact" method="post"><input name="email"><input name="msg"></form>
<script src="/static/app.js"></script></body></html>`

const siteJS = `const api = "/api/v1";
fetch("/api/v1/items"); fetch("/api/v1/users/7"); fetch("/api/v1/orders?status=open");`

func newSite(t testing.TB) *Site { return newSiteTLS(t, false) }

func newSiteTLS(t testing.TB, tls bool) *Site {
	t.Helper()
	s := &Site{Wire: newWire(), status: map[string]int{}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r) })
	if tls {
		s.Server = httptest.NewTLSServer(h)
	} else {
		s.Server = httptest.NewServer(h)
	}
	t.Cleanup(s.Server.Close)
	return s
}

// SetStatus makes path answer with code.
func (s *Site) SetStatus(path string, code int) {
	s.mu.Lock()
	s.status[path] = code
	s.mu.Unlock()
}

// SetDelay makes every answer wait.
func (s *Site) SetDelay(d time.Duration) { s.mu.Lock(); s.delay = d; s.mu.Unlock() }

func (s *Site) serve(w http.ResponseWriter, r *http.Request) {
	s.Wire.addHTTP(r.Method, s.URL+r.RequestURI)
	s.mu.Lock()
	d, code := s.delay, s.status[r.URL.Path]
	s.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
	if code != 0 {
		w.WriteHeader(code)
		fmt.Fprintf(w, "status %d", code)
		return
	}
	switch p := r.URL.Path; {
	case p == "/":
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, siteIndex)
	case p == "/static/app.js":
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, siteJS)
	case p == "/static/site.css":
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprint(w, "body{margin:0}")
	case p == "/static/logo.png":
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "\x89PNG\r\n\x1a\n")
	case p == "/robots.txt":
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\n")
	case p == "/about", p == "/products", p == "/search", p == "/contact", p == "/admin/", p == "/admin", p == "/backup":
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><title>%s</title><body><h1>%s</h1><a href=\"/\">home</a></body></html>", p, p)
	case p == "/old":
		http.Redirect(w, r, "/about", http.StatusMovedPermanently)
	case p == "/graphql" && r.Method == http.MethodPost:
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"errors":[{"message":"introspection is disabled"}]}`)
	case p == "/logout":
		fmt.Fprint(w, "bye")
	case strings.HasPrefix(p, "/api/v1/"):
		// The API answers a signed-in session only: Bearer t-NAME.
		w.Header().Set("Content-Type", "application/json")
		who := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer t-")
		if who == "" || who == r.Header.Get("Authorization") {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"sign in"}`)
			return
		}
		fmt.Fprintf(w, `{"path":%q,"owner":%q,"ok":true}`, p, who)
	default:
		http.NotFound(w, r)
	}
}

// Host is the site's host:port.
func (s *Site) Host() string {
	return strings.TrimPrefix(strings.TrimPrefix(s.URL, "https://"), "http://")
}
