package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// publicStartApp is the triage app: "/" is the same for everyone and links
// to /app/pN; sid=good is accepted for the first live requests, then the
// server forgets it without clearing the cookie and /app/* answers 302 to
// /login.php. after counts the requests sent once it forgot.
type publicStartApp struct {
	mu     sync.Mutex
	n      int
	live   int
	after  int
	always bool // /app/* redirects for everyone, session or not
}

func (a *publicStartApp) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.n++
		c, _ := r.Cookie("sid")
		authed := c != nil && c.Value == "good" && a.n <= a.live && !a.always
		if a.n > a.live {
			a.after++
		}
		a.mu.Unlock()
		var links strings.Builder
		for i := 1; i <= 24; i++ {
			fmt.Fprintf(&links, "<li><a href='/app/p%d'>page %d</a></li>", i, i)
		}
		switch {
		case r.URL.Path == "/":
			fmt.Fprintf(w, "<html><head><title>Welcome</title></head><body><ul>%s</ul></body></html>", links.String())
		case r.URL.Path == "/login.php":
			fmt.Fprint(w, `<html><head><title>Login</title></head><body><form method=post><input name=u><input type=password name=p></form></body></html>`)
		case strings.HasPrefix(r.URL.Path, "/app"):
			if !authed {
				http.Redirect(w, r, "/login.php", http.StatusFound)
				return
			}
			fmt.Fprintf(w, "<html><head><title>%s</title></head><body><ul>%s</ul></body></html>", r.URL.Path, links.String())
		default:
			http.NotFound(w, r)
		}
	})
}

func (a *publicStartApp) sentAfter() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.after
}

// With a start page that looks the same signed in and out, a page that
// answered 200 with the session and then a redirect to a sign-in page is the
// end of the session: the run stops with the session failure within a few
// requests of it, not at its budget.
func TestCookieRunOnAPublicStartPageStopsWhenAProtectedPageRedirectsToSignIn(t *testing.T) {
	t.Chdir(t.TempDir())
	app := &publicStartApp{live: 4}
	srv := httptest.NewServer(app.handler())
	defer srv.Close()
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths",
		"-no-favicon", "-no-tech", "-cookie", "sid=good", "-rate", "200", "-max-requests", "40", "-db", "s.db", "-ledger", "off", "-json")
	if code != exitPartial {
		t.Fatalf("exit %d, want 3 (the session failure):\n%s", code, errOut)
	}
	if got := app.sentAfter(); got > 8 {
		t.Errorf("%d requests went out after the session ended, want a few", got)
	}
	loss, _ := sumMap(t, errOut)["session_lost"].(map[string]any)
	if loss == nil {
		t.Fatalf("no session_lost in the summary:\n%s", errOut)
	}
	if asked, _ := loss["asked_since_good_check"].(float64); asked < 1 || asked > 8 {
		t.Errorf("asked_since_good_check %v, want the few GETs since the last good check", loss["asked_since_good_check"])
	}
	if !strings.Contains(errOut, "/login.php") {
		t.Errorf("the failure does not name the sign-in page:\n%s", errOut)
	}
}

// Starting on a protected page stops, as it did before.
func TestCookieRunStartingOnAProtectedPageStillStops(t *testing.T) {
	t.Chdir(t.TempDir())
	app := &publicStartApp{live: 0}
	srv := httptest.NewServer(app.handler())
	defer srv.Close()
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/app/p1", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths",
		"-no-favicon", "-no-tech", "-cookie", "sid=good", "-rate", "200", "-max-requests", "40", "-db", "s.db", "-ledger", "off", "-json")
	if code != exitPartial {
		t.Fatalf("exit %d, want 3:\n%s", code, errOut)
	}
	if got := app.sentAfter(); got > 8 {
		t.Errorf("%d requests sent, want a handful", got)
	}
}

// A site whose /app pages redirect to sign-in for everyone, with the session
// as without it, never answered 200 with the session: that is its own
// answer, not the end of a session, and the run goes on to its end.
func TestAnAlwaysRedirectedPageIsNotTheEndOfTheSession(t *testing.T) {
	t.Chdir(t.TempDir())
	app := &publicStartApp{live: 1 << 30, always: true}
	srv := httptest.NewServer(app.handler())
	defer srv.Close()
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths",
		"-no-favicon", "-no-tech", "-cookie", "sid=good", "-rate", "200", "-max-requests", "40", "-db", "s.db", "-ledger", "off", "-json")
	if strings.Contains(errOut, "session_lost") || strings.Contains(errOut, "the session ended") {
		t.Fatalf("a page that always redirects was taken for the end of the session (exit %d):\n%s", code, errOut)
	}
}
