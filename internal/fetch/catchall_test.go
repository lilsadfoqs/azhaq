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

// named asks paths a script names, as run does: each is registered, then
// asked and judged.
func named(t *testing.T, srv *httptest.Server, paths ...string) {
	t.Helper()
	for _, p := range paths {
		NoteNamed(srv.URL + p)
		catchAll(t, srv, p)
	}
}

// A directory whose control is the origin's shell holds its script-named
// paths once CatchAllStop of them have answered with the shell; a directory
// nothing was asked in, or whose control is something else, is asked.
func TestCatchAllHeld(t *testing.T) {
	Reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/docs/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs/guide" {
			_, _ = w.Write([]byte(`<title>Guide</title>real page`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><app-root></app-root>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if CatchAllHeld(srv.URL+"/app/a/x", CatchAllStop) {
		t.Fatal("held before any answer")
	}
	named(t, srv, "/app/a/1", "/app/a/2")
	if CatchAllHeld(srv.URL+"/app/a/4", CatchAllStop) {
		t.Error("held after fewer answers than the stop")
	}
	named(t, srv, "/app/a/3")
	if !CatchAllHeld(srv.URL+"/app/a/4", CatchAllStop) {
		t.Error("a path in a directory whose own paths answered the shell is not held")
	}
	if CatchAllHeld(srv.URL+"/app/b/1", CatchAllStop) {
		t.Error("a directory nothing was asked in is held")
	}
	if CatchAllHeld(srv.URL+"/app/a/4", 0) {
		t.Error("held with the stop at 0")
	}
	named(t, srv, "/docs/guide")
	if CatchAllHeld(srv.URL+"/docs/other", CatchAllStop) {
		t.Error("a directory whose control is a 404 is held")
	}
}

// A directory of an app whose unknown paths answer the shell, API routes
// included, is not held for it: its routes answer for themselves.
func TestCatchAllHeldAsksRealRoutesInAShellDirectory(t *testing.T) {
	Reset()
	mux := http.NewServeMux()
	for _, p := range []string{"/api/users", "/api/orders", "/api/items", "/api/stock"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"path":%q,"rows":[]}`, r.URL.Path)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<!doctype html><title>App</title><app-root></app-root>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// The origin answers the shell elsewhere, and /api/ asks for its control.
	named(t, srv, "/about", "/login", "/register", "/api/users", "/api/orders", "/api/items")
	if CatchAllHeld(srv.URL+"/api/stock", CatchAllStop) {
		t.Error("a real route is held because its directory's unknown paths answer the shell")
	}
	if !CatchAllHeld(srv.URL+"/contact", CatchAllStop) {
		t.Error("the shell's own directory, three of its paths answered with it, is not held")
	}
}

// A directory whose unknown paths answer an error page says nothing of the
// paths that exist: they are asked, whatever the origin's other answers.
func TestCatchAllHeldAsksAfterAnErrorPage(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.URL.Path == "/api/Challenges" {
				_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "<title>Error: Unexpected path: %s</title>", r.URL.Path)
			return
		}
		_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><app-root></app-root>`))
	}))
	t.Cleanup(srv.Close)
	named(t, srv, "/about", "/login", "/register", "/api/old1", "/api/old2", "/api/old3")
	if CatchAllHeld(srv.URL+"/api/Challenges", CatchAllStop) {
		t.Error("a route is held because its directory answers an error page for paths that do not exist")
	}
}

// A directory whose script-named paths answer for themselves before the
// shell has answered CatchAllStop of them is asked whole, though its control
// is the shell.
func TestCatchAllHeldGivesWayToRealAnswers(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/files/real") {
			_, _ = w.Write([]byte(`<title>` + r.URL.Path + `</title>real`))
			return
		}
		_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><app-root></app-root>`))
	}))
	t.Cleanup(srv.Close)
	named(t, srv, "/files/real1", "/files/gone1", "/files/real2", "/files/gone2", "/files/real3", "/files/gone3")
	if CatchAllHeld(srv.URL+"/files/gone4", CatchAllStop) {
		t.Error("held although as many paths answered for themselves as answered the shell")
	}
}

// An answer whose control failed is no verdict: it counts neither for the
// page nor for a real route, so a budget that refused the controls does not
// make a directory look real.
func TestCatchAllUnjudgedAnswersSayNothing(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ProbeToken()) {
			panic(http.ErrAbortHandler) // the control gets no answer
		}
		_, _ = w.Write([]byte(`<!doctype html><title>Shop</title><app-root></app-root>`))
	}))
	t.Cleanup(srv.Close)
	named(t, srv, "/app/a/1", "/app/a/2", "/app/a/3", "/app/a/4")
	if st, _ := CatchAllDir(srv.URL+"/app/a/5", CatchAllStop); st != DirUnknown {
		t.Errorf("state %d: answers that were not judged decided the directory", st)
	}
}
