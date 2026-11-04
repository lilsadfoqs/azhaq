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
		} else if d.dead[tok] && r.URL.Path != "/login.php" {
			d.late[tok] = append(d.late[tok], r.URL.Path)
		}
		if r.URL.Path == "/login.php" && r.Method == http.MethodPost {
			d.next++
			tok = fmt.Sprintf("sess-%d", d.next)
			d.live[tok] = 0
		}
		d.mu.Unlock()
		switch {
		case r.URL.Path == "/login.php":
			if r.Method == http.MethodPost {
				http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: tok, Path: "/"})
				redirect("index.php")
				return
			}
			fmt.Fprint(w, `<html><body><form action="login.php" method=post><input name=username><input type=password name=password><input type=submit name=Login value=Login></form></body></html>`)
		case r.URL.Path == "/logout.php":
			redirect(login)
		case !ok:
			redirect(login)
		case r.URL.Path == "/" || r.URL.Path == "/index.php":
			var links strings.Builder
			for i := 1; i <= 12; i++ {
				fmt.Fprintf(&links, `<a href="/v/%d.php">v%d</a> `, i, i)
			}
			fmt.Fprintf(w, `<html><body>%s <a href="/logout.php">Logout</a></body></html>`, links.String())
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
