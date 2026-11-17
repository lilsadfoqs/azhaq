package fetch

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// prefixApp: the root and every unknown path answer a shell (200), but under
// /api and /rest an error page names the path asked, in each form an error page
// uses it. /api/real is a route of its own that also answers 500, with
// another body.
func prefixApp(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/api/real":
			w.WriteHeader(500)
			fmt.Fprint(w, "<title>Error</title><h1>database is down</h1>")
		case p == "/api" || strings.HasPrefix(p, "/api/") || p == "/rest" || strings.HasPrefix(p, "/rest/"):
			w.WriteHeader(500)
			fmt.Fprintf(w, "<title>Error: Unexpected path: %s</title><h1>Error: Unexpected path: %s</h1><a href=%q>%s</a>",
				html.EscapeString(p), p, "?from="+url.QueryEscape(p), html.EscapeString(p))
		default:
			fmt.Fprint(w, "<html><title>App</title><body>shell</body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

// prefixControl asks path and says which control its answer is also the
// answer of (nil: none), and whether it is the origin's catch-all.
func prefixControl(t *testing.T, srv *httptest.Server, path string) (*Control, bool) {
	t.Helper()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+path)
	if err != nil {
		t.Fatal(err)
	}
	shell := CatchAll(context.Background(), srv.Client(), res)
	if shell {
		return nil, true // a caller labels only what is not the catch-all already
	}
	return PrefixControl(context.Background(), srv.Client(), res), false
}

// A path whose answer names itself, an error page, is labelled with the
// control of the prefix it opens when that control answers the same once each
// path is taken out; the control is one request for the prefix, the row is
// not the origin's catch-all (it is listed), and a route that answers 500 with
// a page of its own is not labelled.
func TestPrefixControlLabelsAnAnswerThatNamesItsPath(t *testing.T) {
	Reset()
	srv, asked := prefixApp(t)
	for _, p := range []string{"/api", "/api/v1", "/rest/user/login", "/api/a&b%20c", "/rest"} {
		ctl, shell := prefixControl(t, srv, p)
		// /api and /rest are in the root, whose catch-all is the shell: the
		// prefix's control is the only one they match. The others are also
		// the catch-all of their own directory, as before.
		if p != "/api" && p != "/rest" {
			if !shell {
				t.Errorf("%s: the catch-all of its directory, as before", p)
			}
			continue
		}
		if ctl == nil || shell {
			t.Errorf("%s: want the label of its prefix's control, listed (control %v, catch-all %v)", p, ctl, shell)
		} else if want := "the answer of " + ctl.URL[len(srv.URL):strings.LastIndex(ctl.URL, "/")+1] + "<random> too: this prefix's catch-all"; ctl.PrefixLabel() != want {
			t.Errorf("%s: label %q, want %q", p, ctl.PrefixLabel(), want)
		}
	}
	if ctl, _ := prefixControl(t, srv, "/api/real"); ctl != nil {
		t.Error("/api/real: a 500 with a page of its own is a route, not the catch-all")
	}
	// controls: the root's, /api/ (the prefix of /api, and the directory of
	// /api/v1 and /api/a&b c), /rest/ (the prefix of /rest) and /rest/user/ (the
	// directory of /rest/user/login). /api/real does not name its path.
	var ctls []string
	for _, p := range asked() {
		if strings.Contains(p, ProbeToken()) {
			ctls = append(ctls, p)
		}
	}
	want := map[string]bool{"/" + ProbeToken(): true, "/api/" + ProbeToken(): true, "/rest/" + ProbeToken(): true, "/rest/user/" + ProbeToken(): true}
	if len(ctls) != len(want) {
		t.Fatalf("controls asked: %v", ctls)
	}
	for _, p := range ctls {
		if !want[p] {
			t.Errorf("unexpected control %s in %v", p, ctls)
		}
	}
}

// The control is asked, never assumed: a prefix whose control answers another
// page leaves the hit as it is, and an answer that does not name its path
// asks nothing more.
func TestPrefixControlIsMeasured(t *testing.T) {
	Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api":
			w.WriteHeader(500)
			fmt.Fprint(w, "Error at /api")
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.WriteHeader(404)
			fmt.Fprint(w, "gone")
		default:
			fmt.Fprint(w, "<title>App</title>shell")
		}
	}))
	t.Cleanup(srv.Close)
	if ctl, _ := prefixControl(t, srv, "/api"); ctl != nil {
		t.Error("/api: its prefix answers 404, not the same page")
	}
}

// A 2xx page that names its own path (a canonical link) is a page of its own:
// no control is asked under it.
func TestPrefixControlIsNotAskedForA200Page(t *testing.T) {
	Reset()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/about") {
			fmt.Fprintf(w, `<link rel="canonical" href="%s"><title>About</title>`, r.URL.Path)
			return
		}
		fmt.Fprint(w, "<title>App</title>shell")
	}))
	t.Cleanup(srv.Close)
	if ctl, _ := prefixControl(t, srv, "/about"); ctl != nil {
		t.Error("/about: a page that answers 200 and names its path is not labelled")
	}
	for _, p := range asked {
		if strings.HasPrefix(p, "/about/") {
			t.Errorf("asked %s: no control under a 2xx page", p)
		}
	}
}
