package fetch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func catchAll(t *testing.T, srv *httptest.Server, path string) bool {
	t.Helper()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+path)
	if err != nil {
		t.Fatal(err)
	}
	return CatchAll(context.Background(), srv.Client(), res)
}

func TestCatchAllSPA(t *testing.T) {
	Reset()
	index := `<!doctype html><title>Shop</title><app-root></app-root><script src="main.js"></script>`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/Users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("No Authorization header was found"))
	})
	mux.HandleFunc("/ftp/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<title>listing /ftp</title><a href="legal.md">legal.md</a>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(index))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, p := range []string{"/admin", "/.git/HEAD", "/assets/x.js", "/a/b/c"} {
		if !catchAll(t, srv, p) {
			t.Errorf("%s: want catch-all", p)
		}
	}
	for _, p := range []string{"/", "/api/Users", "/ftp/"} {
		if catchAll(t, srv, p) {
			t.Errorf("%s: real page reported as catch-all", p)
		}
	}
}

func TestCatchAllEchoesPath(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/products" {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<h1>Error: Unexpected path: %s</h1><p>at %s</p>", r.URL.Path, r.URL.Path)
	}))
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/rest/user/login") {
		t.Error("echoing error page: want catch-all")
	}
	if catchAll(t, srv, "/rest/products") {
		t.Error("real endpoint reported as catch-all")
	}
}

func TestCatchAllRedirect(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte("<title>Login</title>"))
		case "/account":
			http.Redirect(w, r, "/login?next=/account&reason=session", http.StatusFound)
		default:
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
		}
	}))
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/wp-admin") {
		t.Error("redirect for every path: want catch-all")
	}
	if catchAll(t, srv, "/account") {
		t.Error("distinct redirect reported as catch-all")
	}
	if catchAll(t, srv, "/login") {
		t.Error("login page reported as catch-all")
	}
}

func TestCatchAllDynamicSoft404(t *testing.T) {
	Reset()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			_, _ = w.Write([]byte("<title>About</title><p>We sell juice since 2014.</p>"))
			return
		}
		fmt.Fprintf(w, "<title>Not found</title>\n<p>Sorry, nothing here.</p>\n<input name=csrf value=%d>", n.Add(1)*7919)
	}))
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/backup") {
		t.Error("soft 404 with a changing token: want catch-all")
	}
	if catchAll(t, srv, "/about") {
		t.Error("real page reported as catch-all")
	}
}

func TestCatchAllPlain404Server(t *testing.T) {
	Reset()
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, probeToken) {
			probes.Add(1)
		}
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	if catchAll(t, srv, "/admin") {
		t.Error("403 on a server with real 404s reported as catch-all")
	}
	if catchAll(t, srv, "/missing") {
		t.Error("404 is not a catch-all")
	}
	catchAll(t, srv, "/admin")
	// 401, 403, 404 and 410 are decided by their status alone (a gated or
	// absent route, never the page an unknown path gets), so no baseline is
	// fetched for them.
	if probes.Load() != 0 {
		t.Errorf("baseline probes %d, want 0 (status decides these)", probes.Load())
	}
}

// The shell the root serves for unknown paths is that answer in every
// directory: only the root is asked for a baseline, and a directory with
// an answer of its own is still told apart.
func TestCatchAllRootShellAsksOneBaseline(t *testing.T) {
	Reset()
	var probes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/user/whoami", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"user":{}}`))
	})
	mux.HandleFunc("/rest/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ProbeToken()) {
			probes.Add(1)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Error: Unexpected path"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ProbeToken()) {
			probes.Add(1)
		}
		_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><app-root></app-root>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if !catchAll(t, srv, "/admin") {
		t.Fatal("/admin: want catch-all")
	}
	for _, p := range []string{"/.well-known/security.txt", "/.git/HEAD", "/swagger/v1/x.json"} {
		if !catchAll(t, srv, p) {
			t.Errorf("%s: want catch-all", p)
		}
	}
	if n := probes.Load(); n != 1 {
		t.Errorf("%d baseline requests, want 1 (the root's)", n)
	}
	if catchAll(t, srv, "/rest/user/whoami") {
		t.Error("/rest/user/whoami: a page of its own reported as the shell")
	}
	if !catchAll(t, srv, "/rest/nothing") {
		t.Error("/rest/nothing: its directory's error page is its catch-all")
	}
}

// With a probe depth of 1 a directory below /rest/ is compared with /rest/'s
// baseline: one request for both, and the same verdicts.
func TestCatchAllProbeDepthSharesTheBaselineAbove(t *testing.T) {
	Reset()
	SetProbeDepth(1)
	t.Cleanup(func() { SetProbeDepth(0) })
	var probes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/user/whoami", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"user":{}}`))
	})
	mux.HandleFunc("/rest/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ProbeToken()) {
			probes.Add(1)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "Error: Unexpected path: %s", r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	if catchAll(t, srv, "/rest/user/whoami") {
		t.Error("/rest/user/whoami: a page of its own reported as the generic answer")
	}
	if !catchAll(t, srv, "/rest/user/nothing") || !catchAll(t, srv, "/rest/admin/nothing") {
		t.Error("an unknown path under /rest/: want catch-all")
	}
	if n := probes.Load(); n != 1 {
		t.Errorf("%d baseline requests, want 1 (/rest/'s)", n)
	}
}

// A probe name is the same for the same salt within a run and differs
// between salts, and a resume (the run's probe token) gets the same names.
func TestProbeNameIsStableWithinARun(t *testing.T) {
	defer SetProbeToken(ProbeToken())
	SetProbeToken("run1token")
	a, b := ProbeName("dirs 0"), ProbeName("dirs 1")
	if a == b || a != ProbeName("dirs 0") {
		t.Errorf("names %q %q", a, b)
	}
	if len(a) < 10 || len(a) > 14 || a[0] < 'a' || a[0] > 'z' {
		t.Errorf("name %q is not 10 to 14 characters starting with a letter", a)
	}
	SetProbeToken("run2token")
	if ProbeName("dirs 0") == a {
		t.Error("another run asked the same name")
	}
}
