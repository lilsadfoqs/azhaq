package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// dvwaSessions is a DVWA-shaped app with real sessions: a form sign-in sets
// PHPSESSID, the pages link to each other, and a session ends when
// /logout.php is asked or, with expireAt, at its expireAt-th request. A
// request with a dead session is sent to login.php (a Location with no
// leading slash, as DVWA sends it).
type dvwaSessions struct {
	mu       sync.Mutex
	next     int
	live     map[string]int  // session → requests it has answered
	dead     map[string]bool // sessions that ended
	expireAt int
	expired  bool
	late     map[string][]string // per session that ended, the paths asked with it afterwards, the request that ended it aside
	// forgetLanding ends the first session once the page the sign-in lands
	// on has been served to it (a proxy that drops the cookie from then on).
	forgetLanding bool
	forgot        bool
	noIcon        bool     // the pages name an empty icon (Chrome asks no /favicon.ico) and a style sheet: the request counts are exact
	reqs          []string // every request in order: METHOD path
}

func (d *dvwaSessions) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := func(to string) {
			w.Header().Set("Location", to)
			w.WriteHeader(http.StatusFound)
		}
		login := "login.php"
		if strings.Count(r.URL.Path, "/") > 1 {
			login = "../login.php"
		}
		d.mu.Lock()
		d.reqs = append(d.reqs, r.Method+" "+r.URL.Path)
		tok := ""
		if c, _ := r.Cookie("PHPSESSID"); c != nil {
			tok = c.Value
		}
		_, ok := d.live[tok]
		if ok {
			d.live[tok]++
			if d.expireAt > 0 && !d.expired && d.live[tok] == d.expireAt || r.URL.Path == "/logout.php" {
				d.expired = d.expired || r.URL.Path != "/logout.php"
				delete(d.live, tok)
				d.dead[tok] = true
				ok = r.URL.Path == "/logout.php" // an expiry answers its own request as a visitor's
			}
		} else if d.dead[tok] && r.URL.Path != "/login.php" && r.URL.Path != "/s.css" {
			d.late[tok] = append(d.late[tok], r.URL.Path)
		}
		if ok && d.forgetLanding && !d.forgot && r.URL.Path == "/index.php" {
			d.forgot = true // this answer is the live one; the session is gone after it
			delete(d.live, tok)
			d.dead[tok] = true
		}
		if r.URL.Path == "/login.php" && r.Method == http.MethodPost {
			d.next++
			tok = fmt.Sprintf("sess-%d", d.next)
			d.live[tok] = 0
		}
		d.mu.Unlock()
		icon := ""
		if d.noIcon {
			icon = `<link rel="icon" href="data:,"><link rel="stylesheet" href="/s.css">`
		}
		switch {
		case r.URL.Path == "/s.css":
			w.Header().Set("Content-Type", "text/css")
		case r.URL.Path == "/login.php":
			if r.Method == http.MethodPost {
				http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: tok, Path: "/"})
				redirect("index.php")
				return
			}
			fmt.Fprint(w, `<html><head>`+icon+`</head><body><form action="login.php" method=post><input name=username><input type=password name=password><input type=submit name=Login value=Login></form></body></html>`)
		case r.URL.Path == "/logout.php":
			redirect(login)
		case !ok:
			redirect(login)
		case r.URL.Path == "/" || r.URL.Path == "/index.php":
			var links strings.Builder
			for i := 1; i <= 12; i++ {
				fmt.Fprintf(&links, `<a href="/v/%d.php">v%d</a> `, i, i)
			}
			fmt.Fprintf(w, `<html><head>%s</head><body>%s <a href="/logout.php">Logout</a></body></html>`, icon, links.String())
		default:
			fmt.Fprintf(w, `<html><body>page %s <a href="/index.php">home</a></body></html>`, r.URL.Path)
		}
	})
}

// A Chrome sign-in run whose session ends while it maps reads the end from
// the answer that shows it (a redirect to login.php, with a relative
// Location as DVWA sends it) and sends nothing more with the dead session
// but what was already in the air: -login signs in again, and -cookie
// stops its signed-in work, exit 3, with the in-flight requests counted and
// named in the summary.
func TestChromeSessionRunsStopAtTheAnswerThatEndsTheSession(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	const parallel = 4
	for _, tc := range []struct {
		name     string
		expireAt int
		cookie   bool
		held     bool // the logout link is held back (no -send-state-changing)
	}{
		{"-login, a logout link", 0, false, false},
		{"-login, expiry", 14, false, false},
		{"-cookie, a logout link", 0, true, false},
		{"-cookie, expiry", 14, true, false},
		{"-cookie, a logout link held back", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &dvwaSessions{expireAt: tc.expireAt, live: map[string]int{}, dead: map[string]bool{}, late: map[string][]string{}}
			srv := httptest.NewServer(app.handler())
			defer srv.Close()
			args := []string{"run", "-url", srv.URL + "/", "-browser", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-parallel", fmt.Sprint(parallel),
				"-db", filepath.Join(t.TempDir(), "s.db"), "-json"}
			if tc.cookie {
				app.live["sess-0"] = 0
				args = append(args, "-cookie", "PHPSESSID=sess-0")
			} else {
				args = append(args, "-login", srv.URL+"/login.php", "-login-user", "admin", "-login-pass", "password")
			}
			if tc.expireAt == 0 && !tc.held {
				// The link ends the session only when it is sent: a found
				// logout is held back by default.
				args = append(args, "-send-state-changing")
			}
			_, errOut, code := cli(t, args...)
			sum := sumMap(t, errOut)
			app.mu.Lock()
			late := map[string][]string{}
			for k, v := range app.late {
				late[k] = v
			}
			app.mu.Unlock()
			// Never the 31 GETs and 19 more of a run that waits for its periodic check.
			for tok, paths := range late {
				if len(paths) > parallel {
					t.Errorf("%d requests carried session %s after it ended, more than the %d in the air: %v", len(paths), tok, parallel, paths)
				}
			}
			loss, _ := sum["session_lost"].(map[string]any)
			if tc.held {
				app.mu.Lock()
				dead := len(app.dead)
				app.mu.Unlock()
				if dead != 0 || loss != nil || code != exitOK {
					t.Errorf("held logout: %d sessions ended, session_lost %v, exit %d", dead, loss, code)
				}
				return
			}
			if !tc.cookie {
				if loss != nil || code != exitOK {
					t.Errorf("signed in again: exit %d, session_lost %v", code, loss)
				}
				return
			}
			if code != exitPartial || loss == nil {
				t.Fatalf("exit %d, want %d, with session_lost: %v", code, exitPartial, sum["failed"])
			}
			urls, _ := loss["in_flight_urls"].([]any)
			if n, _ := loss["in_flight"].(float64); int(n) != len(urls) || len(urls) > parallel {
				t.Errorf("in_flight %v with %d URLs", loss["in_flight"], len(urls))
			}
			if loss["first_answer"] == "" {
				t.Errorf("no first answer: %v", loss)
			}
			t.Logf("late %v; loss %v", late, loss)
		})
	}
}

// A session that ends right after the sign-in (a proxy dropping the cookie
// as an expiry would) is noticed at the first check: the page the sign-in
// ended on answered 200 in Chrome, and the run's own request for it, with the
// same session, is sent to the sign-in page. The run signs in again and maps
// with the new session, or, with no budget for a new sign-in, stops with the
// session failure and sends no mapping request after that check.
func TestChromeSessionEndedRightAfterSignInIsNoticedAtTheFirstCheck(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	run := func(t *testing.T, budget string) (*dvwaSessions, map[string]any, int) {
		app := &dvwaSessions{forgetLanding: true, noIcon: true, live: map[string]int{}, dead: map[string]bool{}, late: map[string][]string{}}
		srv := httptest.NewServer(app.handler())
		t.Cleanup(srv.Close)
		args := []string{"run", "-url", srv.URL + "/", "-browser", "-allow", "127.0.0.1", "-sources", "none", "-no-paths",
			"-login", srv.URL + "/login.php", "-login-user", "admin", "-login-pass", "password", "-max-requests", budget,
			"-db", filepath.Join(t.TempDir(), "s.db"), "-json"}
		_, errOut, code := cli(t, args...)
		return app, sumMap(t, errOut), code
	}
	t.Run("signs in again and goes on", func(t *testing.T) {
		app, sum, code := run(t, "200")
		app.mu.Lock()
		defer app.mu.Unlock()
		if code != exitOK || sum["session_lost"] != nil {
			t.Fatalf("exit %d, session_lost %v, failed %v", code, sum["session_lost"], sum["failed"])
		}
		if !strings.Contains(fmt.Sprint(sum["notes"]), "signed in again") || !strings.Contains(fmt.Sprint(sum["notes"]), "answered 200 in Chrome") {
			t.Errorf("no note that the session ended and was renewed: %v", sum["notes"])
		}
		// The dead session was asked once: the check, and nothing after it.
		for tok, paths := range app.late {
			if len(paths) != 1 || paths[0] != "/index.php" {
				t.Errorf("session %s, dead, was sent %v: want only the check", tok, paths)
			}
		}
		if len(app.late) != 1 {
			t.Errorf("%d sessions ended, want 1", len(app.late))
		}
	})
	t.Run("no room for a new sign-in stops the run", func(t *testing.T) {
		// The sign-in takes 5 requests (the form and its sheet, the POST, the
		// landing page and its sheet) and the check 1: no room for another.
		app, sum, code := run(t, "6")
		app.mu.Lock()
		defer app.mu.Unlock()
		if code != exitPartial || sum["session_lost"] == nil {
			t.Fatalf("exit %d, session_lost %v, failed %v", code, sum["session_lost"], sum["failed"])
		}
		loss, _ := sum["session_lost"].(map[string]any)
		if n, _ := loss["asked_since_good_check"].(float64); n < 1 {
			t.Errorf("the requests sent since the sign-in are not counted: %v", loss)
		}
		// After the check (the second GET of /index.php) nothing but a sign-in page reached the server.
		seen := 0
		for _, r := range app.reqs {
			if seen >= 2 && r != "GET /login.php" {
				t.Errorf("request %q after the check that found the session ended: %v", r, app.reqs)
			}
			if r == "GET /index.php" {
				seen++
			}
		}
		if seen != 2 {
			t.Errorf("want the landing page and the check, got %v", app.reqs)
		}
		if !strings.Contains(fmt.Sprint(sum["failed"]), "signing in again failed") {
			t.Errorf("the failure does not say why: %v", sum["failed"])
		}
	})
}
