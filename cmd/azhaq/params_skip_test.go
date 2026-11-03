package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A Juice Shop-like site for the parameter search: /rest/products/search
// reads q; /about is a route of the shell (every unknown path answers it);
// /rest/user/whoami and /admin refuse. hits counts the requests of each path.
func paramSite(t *testing.T) (*httptest.Server, func(p string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	shell := `<html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root><a href="/about">about</a><a href="/rest/products/search">search</a><a href="/rest/user/whoami">me</a><a href="/admin">admin</a></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/rest/products/search":
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Has("q") {
				io.WriteString(w, `{"status":"success","data":[{"id":1,"name":"Apple Juice"}]}`)
				return
			}
			io.WriteString(w, `{"status":"success","data":[]}`)
		case "/rest/user/whoami":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"No Authorization header was found"}`)
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "forbidden")
		default:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, shell)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[p]
	}
}

func runParams(t *testing.T, srv *httptest.Server, extra ...string) report {
	t.Helper()
	words := filepath.Join(t.TempDir(), "words.txt")
	var ws []string
	for i := 0; i < 40; i++ {
		ws = append(ws, fmt.Sprintf("name%d", i))
	}
	ws = append(ws, "q", "search", "id")
	if err := os.WriteFile(words, []byte(strings.Join(ws, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
		"-params", words, "-json", "-quiet", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
	_, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	return lastReport(t, errOut)
}

// A page whose answer to the run was the one an unknown path gets, or a
// refusal, is not asked the whole list again: its request count is the run's
// own, and a note says why each was left out. The page that reads q is searched.
// -params-all searches them all.
func TestParamsSkipsPagesThatAnsweredAsTheControlOrRefused(t *testing.T) {
	srv, hits := paramSite(t)
	rep := runParams(t, srv)
	for _, p := range []string{"/about", "/rest/user/whoami", "/admin"} {
		if n := hits(p); n > 2 {
			t.Errorf("%s was sent %d requests: the list was asked of a page that read no name", p, n)
		}
	}
	if n := hits("/rest/products/search"); n < 4 {
		t.Errorf("/rest/products/search was sent %d requests: it reads q and is searched", n)
	}
	notes := strings.Join(rep.Notes, "\n")
	for _, want := range []string{
		"/about: not searched, its answer is the one the origin gives a path that cannot exist (GET /",
		"/rest/user/whoami: not searched, it refused the request: it answered 401",
		"/admin: not searched, it refused the request: it answered 403",
		"-params-all searches it",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes lack %q:\n%s", want, notes)
		}
	}
	if strings.Contains(notes, "/rest/products/search: not searched") {
		t.Errorf("the page that reads q was left out:\n%s", notes)
	}

	srv2, hits2 := paramSite(t)
	runParams(t, srv2, "-params-all")
	for _, p := range []string{"/about", "/rest/user/whoami", "/admin"} {
		if n := hits2(p); n < 4 {
			t.Errorf("-params-all: %s was sent %d requests, want it searched", p, n)
		}
	}
}
