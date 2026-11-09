package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

// sweepApp is a server that counts each GET by its decoded path and query.
type sweepApp struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []string
}

func newSweepApp(t *testing.T) *sweepApp {
	t.Helper()
	a := &sweepApp{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		a.mu.Lock()
		a.got = append(a.got, line)
		a.mu.Unlock()
		switch r.URL.Path {
		case "/logout", "/reset", "/console", "/users/v1", "/about", "/#top":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "ok "+r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *sweepApp) count(line string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, g := range a.got {
		if g == line {
			n++
		}
	}
	return n
}

func (a *sweepApp) total() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

func sweepDB(t *testing.T) string { return filepath.Join(t.TempDir(), "d.db") }
