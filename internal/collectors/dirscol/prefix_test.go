package dirscol

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// echoApp answers the shell for the root and every unknown path, and a 500
// error page that names the requested path (in its title, its heading, an
// escaped title and a query-encoded link) for /api, /rest and everything
// under them, except /api/real: a route that also answers 500, with a page of
// its own that names its path.
func echoApp(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		log = append(log, r.URL.Path)
		mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/api/real":
			w.WriteHeader(500)
			fmt.Fprintf(w, "<title>Error</title><h1>the database is down at %s</h1>", p)
		case p == "/api" || p == "/rest" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/rest/"):
			w.WriteHeader(500)
			fmt.Fprintf(w, "<title>Error: Unexpected path: %s</title><h1>Error: Unexpected path: %s</h1><a href=%q>again</a>",
				html.EscapeString(p), p, "?from="+url.QueryEscape(p))
		default:
			fmt.Fprint(w, "<html><title>App</title><body>the same shell for every route</body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), log...) }
}

// A hit that answers with an error page naming its own path and, with that
// path taken out, is the answer of a control asked under the prefix it opens is
// listed, labelled as that prefix's catch-all, and counted: no hit goes. One
// control serves every hit under its prefix (/api/ answers for /api and
// /api/x/y), and a route that answers 500 with another body is not labelled.
func TestSweepLabelsAHitThatIsItsPrefixsCatchAll(t *testing.T) {
	fetch.Reset()
	srv, asked := echoApp(t)
	words := []string{"api", "api/v1", "api/a&b", "api/x/y", "rest/user/login", "api/real", "nothing"}
	c := New(srv.Client(), Options{Words: words, Rate: 1000, Set: allStatuses()})
	rows, summary := sweepRows(t, c, srv.URL+"/")
	labelled := map[string]string{}
	for p, m := range rows {
		if m["prefix_catchall"] != nil {
			if m["catchall"] != nil {
				t.Errorf("%s: labelled and folded", p)
			}
			ctl := m["prefix_catchall"].(map[string]any)
			labelled[p] = strings.TrimPrefix(ctl["url"].(string), srv.URL)
		}
	}
	for p, prefix := range map[string]string{"/api": "/api/", "/api/x/y": "/api/", "/rest/user/login": "/rest/user/login/"} {
		if !strings.HasPrefix(labelled[p], prefix) || strings.Count(labelled[p], "/") != strings.Count(prefix, "/") {
			t.Errorf("%s: control %q, want one under %s (rows %v)", p, labelled[p], prefix, rows[p])
		}
	}
	// Every hit is a row: the two the directory's own control folds (as before),
	// the three labelled, and the route of its own.
	if len(rows) != 6 || len(labelled) != 3 || rows["/api/real"] == nil || rows["/api/real"]["prefix_catchall"] != nil || rows["/api/real"]["catchall"] != nil {
		t.Errorf("%d rows, labelled %v, /api/real %v", len(rows), labelled, rows["/api/real"])
	}
	// 7 words, 4 calibration names, and one control for each of /api/ (the
	// directory's, and the prefix of /api), /api/real/ (measured, not the same
	// page) and /rest/user/login/.
	if n := len(asked()); n != 7+4+3 || summary["controls"] != 3.0 || summary["folded"] != 2.0 || summary["prefix_catchall"] != 3.0 {
		t.Errorf("%d requests, summary %v", len(asked()), summary)
	}

	// Calibration off is the user's own: no control, no label.
	fetch.Reset()
	srv2, asked2 := echoApp(t)
	c = New(srv2.Client(), Options{Words: words, Rate: 1000, NoCalibration: true, Set: allStatuses()})
	rows, summary = sweepRows(t, c, srv2.URL+"/")
	for p, m := range rows {
		if m["catchall"] != nil || m["prefix_catchall"] != nil {
			t.Errorf("-ac=false marked %s", p)
		}
	}
	if len(asked2()) != len(words) || summary["controls"] != 0.0 {
		t.Errorf("-ac=false: %d requests, summary %v", len(asked2()), summary)
	}
}

// A control that answers another page does not label the hit, whatever the
// status: it is measured.
func TestSweepDoesNotLabelAHitWhosePrefixAnswersAnotherPage(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/api":
			w.WriteHeader(500)
			fmt.Fprintf(w, "Error at %s", p)
		case strings.HasPrefix(p, "/api/"):
			w.WriteHeader(404)
			fmt.Fprint(w, "no such route")
		default:
			fmt.Fprint(w, "<title>App</title>shell")
		}
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"api"}, Rate: 1000, Set: allStatuses()})
	rows, summary := sweepRows(t, c, srv.URL+"/")
	if rows["/api"] == nil || rows["/api"]["prefix_catchall"] != nil || summary["controls"] != 1.0 || summary["prefix_catchall"] != 0.0 {
		t.Errorf("/api is listed, unlabelled: %v, summary %v", rows["/api"], summary)
	}
}

// A directory (a redirect to its own path with a slash) names its path in its
// Location and its body, as every directory does: it asks no control.
func TestSweepAsksNoControlForADirectoryRedirect(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs" {
			http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
			return
		}
		fmt.Fprint(w, "<title>App</title>shell")
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"docs"}, Rate: 1000, Set: allStatuses()})
	rows, summary := sweepRows(t, c, srv.URL+"/")
	if rows["/docs"] == nil || summary["controls"] != 0.0 {
		t.Errorf("/docs is listed and asks no control: %v, summary %v", rows["/docs"], summary)
	}
}

// A page that answers 2xx and names its own path (a canonical link) is a page
// of its own, not an error page: no control is asked for it.
func TestSweepAsksNoControlForAPageThatAnswers200(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/about" {
			fmt.Fprint(w, `<link rel="canonical" href="/about"><title>About</title>`)
			return
		}
		fmt.Fprint(w, "<title>App</title>shell")
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"about"}, Rate: 1000, Set: allStatuses()})
	rows, summary := sweepRows(t, c, srv.URL+"/")
	if rows["/about"] == nil || summary["controls"] != 0.0 {
		t.Errorf("/about is listed and asks no control: %v, summary %v", rows["/about"], summary)
	}
}
