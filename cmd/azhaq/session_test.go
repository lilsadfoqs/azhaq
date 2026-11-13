package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/types"
)

// A -cookie run has no sign-in page, yet a request that ends the session
// with a plain redirect to it must stop the run at once: the page a visitor
// without the session is sent to from the check page is the sign-in page.
func TestCookieRunStopsAtTheRequestThatEndedItsSession(t *testing.T) {
	var mu sync.Mutex
	live := true
	var anon []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		c, _ := r.Cookie("SID")
		ok := c != nil && c.Value == "good" && live
		if !ok {
			anon = append(anon, r.URL.Path)
		}
		switch {
		case r.URL.Path == "/logout":
			live = false
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/login":
			_, _ = w.Write([]byte("login"))
		case !ok:
			http.Redirect(w, r, "/login", http.StatusFound)
		default:
			_, _ = w.Write([]byte("page"))
		}
	}))
	defer srv.Close()
	fetch.Reset()
	defer fetch.Reset()
	fetch.Extra = http.Header{"Cookie": {"SID=good"}}
	ctx := context.Background()
	rep := &report{}
	watchSession(ctx, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}, "", "", nil, nil, rep, 0)
	if got := fetch.SignInPath(); got != "/login" {
		t.Fatalf("sign-in page %q, want /login (where the check page sends a visitor)", got)
	}
	mu.Lock()
	anon = nil // the check's own request without the session is not the run's
	mu.Unlock()
	var lost error
	for _, p := range []string{"/", "/a", "/logout", "/b", "/c", "/d"} {
		if _, _, err := fetch.Do(ctx, srv.Client(), srv.URL+p); err != nil {
			lost = err
			if p != "/b" {
				t.Errorf("%s refused: the run stops at the first request after /logout, got %v", p, err)
			}
			break
		}
	}
	if !errors.Is(lost, neterr.ErrSessionLost) {
		t.Fatalf("the request after /logout was not refused: %v", lost)
	}
	if !strings.Contains(lost.Error(), "/logout") {
		t.Errorf("the failure does not name the URL that ended the session: %v", lost)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range anon {
		if p == "/b" || p == "/c" || p == "/d" {
			t.Errorf("a request went out without the session after it ended: %s", p) // "/" is the check itself
		}
	}
}

// A server may redirect to the sign-in page with a relative Location
// ("login.php", as DVWA does): the run reads it against the page that was
// asked, so the request after the one that ended the session is already
// refused, not the 50th.
func TestRelativeRedirectToSignInStopsTheRun(t *testing.T) {
	for _, tc := range []struct {
		name  string
		login func(base string) string
	}{
		{"login given", func(base string) string { return base + "/login.php" }},
		{"login found from the check page", func(string) string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			live := true
			var anon []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				c, _ := r.Cookie("SID")
				ok := c != nil && c.Value == "good" && live
				if !ok && r.URL.Path != "/login.php" {
					anon = append(anon, r.URL.Path)
				}
				switch {
				case r.URL.Path == "/logout.php":
					live = false
					w.Header().Set("Location", "login.php")
					w.WriteHeader(http.StatusFound)
				case r.URL.Path == "/login.php":
					_, _ = w.Write([]byte("login"))
				case !ok:
					w.Header().Set("Location", "login.php")
					w.WriteHeader(http.StatusFound)
				default:
					_, _ = w.Write([]byte("page"))
				}
			}))
			defer srv.Close()
			fetch.Reset()
			defer fetch.Reset()
			fetch.Extra = http.Header{"Cookie": {"SID=good"}}
			ctx := context.Background()
			watchSession(ctx, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/index.php"}}}, "", tc.login(srv.URL), nil, nil, &report{}, 0)
			mu.Lock()
			anon = nil
			mu.Unlock()
			var lost error
			var sent []string
			for _, p := range []string{"/index.php", "/a", "/logout.php", "/b", "/c", "/d"} {
				if _, _, err := fetch.Do(ctx, srv.Client(), srv.URL+p); err != nil {
					lost = err
					break
				}
				sent = append(sent, p)
			}
			if !errors.Is(lost, neterr.ErrSessionLost) {
				t.Fatalf("the requests after /logout.php were not refused: %v (sent %v)", lost, sent)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range anon {
				if p != "/logout.php" && p != "/index.php" {
					t.Errorf("a request went out without the session after it ended: %s", p)
				}
			}
		})
	}
}

// With many requests in the air when the answer that ends the session
// comes, none starts after it: the ones already out are the only ones
// answered without the session, the failure counts them, and the server
// sees no more. The session ends by a /logout link the crawl finds, or the
// server expires it after 10 requests (answering with a redirect to the
// sign-in page, or with a cookie that clears it).
func TestParallelRunSendsNothingNewAfterTheSessionEnds(t *testing.T) {
	const workers = 8
	for _, mode := range []string{"logout link", "expiry redirect", "expiry clears cookie"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			live, served := true, 0
			var anon []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				served++
				if mode != "logout link" && served == 10 || r.URL.Path == "/logout.php" {
					live = false
				}
				ok := live
				if c, _ := r.Cookie("SID"); c == nil || c.Value != "good" {
					ok = false
				}
				if !ok && r.URL.Path != "/login.php" {
					anon = append(anon, r.URL.Path)
				}
				mu.Unlock()
				switch {
				case r.URL.Path == "/login.php":
					_, _ = w.Write([]byte("login"))
				case r.URL.Path == "/logout.php" || !ok:
					if mode == "expiry clears cookie" && r.URL.Path != "/logout.php" {
						http.SetCookie(w, &http.Cookie{Name: "SID", Value: "", MaxAge: -1, Path: "/"})
						_, _ = w.Write([]byte("please sign in"))
						return
					}
					w.Header().Set("Location", "login.php")
					w.WriteHeader(http.StatusFound)
				default:
					time.Sleep(2 * time.Millisecond)
					_, _ = w.Write([]byte("page"))
				}
			}))
			defer srv.Close()
			fetch.Reset()
			defer fetch.Reset()
			fetch.Extra = http.Header{"Cookie": {"SID=good"}}
			ctx := context.Background()
			watchSession(ctx, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/index.php"}}}, "", srv.URL+"/login.php", nil, nil, &report{}, 0)
			mu.Lock()
			anon, served = nil, 0
			mu.Unlock()
			var wg sync.WaitGroup
			var lostN atomic.Int64
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 40; i++ {
						p := fmt.Sprintf("/p%d-%d", w, i)
						if w == 0 && i == 5 && mode == "logout link" {
							p = "/logout.php"
						}
						if _, _, err := fetch.Do(ctx, srv.Client(), srv.URL+p); err != nil {
							if errors.Is(err, neterr.ErrSessionLost) {
								lostN.Add(1)
							}
							return
						}
					}
				}()
			}
			wg.Wait()
			if int(lostN.Load()) != workers {
				t.Errorf("%d of %d workers were refused with the session lost", lostN.Load(), workers)
			}
			mu.Lock()
			defer mu.Unlock()
			// The guard asks its check page once to confirm the end; that is
			// not new work, so it is counted apart.
			var work, checks []string
			for _, p := range anon {
				if p == "/index.php" {
					checks = append(checks, p)
				} else {
					work = append(work, p)
				}
			}
			if len(work) > workers {
				t.Errorf("%d requests reached the server without the session, more than the %d in the air: %v", len(work), workers, work)
			}
			if len(checks) > 1 {
				t.Errorf("the check page was asked %d times after the session ended, not once: %v", len(checks), anon)
			}
			var sl *neterr.SessionLost
			if !errors.As(fetch.SessionLost(), &sl) {
				t.Fatalf("no failure: %v", fetch.SessionLost())
			}
			if len(sl.InFlight) > workers || sl.Answer == "" {
				t.Errorf("in flight %v, first answer %q; %s", sl.InFlight, sl.Answer, sl.Msg)
			}
			if want := plural1(len(sl.InFlight), "GET") + " answered after that answer, already in flight"; len(sl.InFlight) > 0 && !strings.Contains(sl.Msg, want) {
				t.Errorf("the message does not count the %d in flight (%q): %s", len(sl.InFlight), want, sl.Msg)
			}
			if len(sl.InFlight) == 0 && !strings.Contains(sl.Msg, "no other GET was in flight") {
				t.Errorf("no GET in flight, and the message does not say so: %s", sl.Msg)
			}
		})
	}
}

func plural1(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// A -login run with no check page that is answered like a session that
// ended (a 401) and cannot sign in again to find out stops with the session
// failure: it does not go on as a visitor.
func TestLoginRunThatCannotSignInAgainToTestA401StopsSending(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("page"))
	}))
	defer srv.Close()
	fetch.Reset()
	defer fetch.Reset()
	fetch.Extra = http.Header{"Cookie": {"SID=good"}}
	ctx := context.Background()
	signIns := 0
	renew := func(context.Context) error { signIns++; return errors.New("the request budget is spent") }
	watchSession(ctx, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}, "", srv.URL+"/login", renew, nil, &report{}, 0)
	if _, _, err := fetch.Do(ctx, srv.Client(), srv.URL+"/admin"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	paths = nil
	mu.Unlock()
	_, _, err := fetch.Do(ctx, srv.Client(), srv.URL+"/next")
	var sl *neterr.SessionLost
	if !errors.As(err, &sl) || signIns != 1 {
		t.Fatalf("err %v after %d sign-ins, want the session failure", err, signIns)
	}
	if !strings.Contains(sl.Msg, "/admin answered 401") || !strings.Contains(sl.Msg, "signing in again to find out failed: the request budget is spent") || !strings.Contains(sl.Msg, "GET asked since the last good check") {
		t.Errorf("the failure does not say why: %s", sl.Msg)
	}
	if _, _, err := fetch.Do(ctx, srv.Client(), srv.URL+"/after"); !errors.Is(err, neterr.ErrSessionLost) {
		t.Errorf("a request after the failure: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 0 {
		t.Errorf("sent after the answer that may have ended the session: %v", paths)
	}
}

// A session given with -cookie or -header that no page shows live, where a
// page turns it away (a 401, or a redirect to a page whose form takes a
// password) as it turns away a visitor, never held: the run stops before any
// other request, and the failure says so.
func TestASessionThatNeverHeldStopsTheRun(t *testing.T) {
	for _, tc := range []struct {
		name, page string
		header     http.Header
		want       string
	}{
		{"cookie and a sign-in redirect", "/account", http.Header{"Cookie": {"sid=dead"}}, "/account answered 302 to /login"},
		{"token and a 401", "/api/me", http.Header{"Authorization": {"Bearer dead"}}, "/api/me answered 401"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked.Add(1)
				switch r.URL.Path {
				case "/":
					_, _ = w.Write([]byte("<title>Home</title>"))
				case "/login":
					_, _ = w.Write([]byte(`<form method=post><input name=user><input type="password" name=pw></form>`))
				case "/account":
					http.Redirect(w, r, "/login", http.StatusFound)
				case "/api/me":
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			defer srv.Close()
			fetch.Reset()
			defer fetch.Reset()
			fetch.Extra = tc.header
			rep := &report{}
			seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + tc.page}}, {Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}
			watchSession(context.Background(), seeds, "", "", nil, nil, rep, 0)
			before := asked.Load()
			_, _, err := fetch.Do(context.Background(), srv.Client(), srv.URL+"/")
			if !errors.Is(err, neterr.ErrSessionLost) {
				t.Fatalf("the run went on with a session that never held: %v", err)
			}
			if got := asked.Load(); got != before {
				t.Errorf("%d requests went out after the check", got-before)
			}
			if !strings.Contains(err.Error(), "does not hold") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the failure %q does not say the session does not hold, and why (%s)", err, tc.want)
			}
		})
	}
}

// A page that answers a visitor and the session alike, and does not turn
// either away, says nothing of the session: the run goes on, and the summary
// says no page showed the session live. A redirect to a page with no
// password field is not a sign-in.
func TestASessionNoPageShowsGoesOnWithANote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/en/", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`<title>Welcome</title><form action=/search><input name=q></form>`))
		}
	}))
	defer srv.Close()
	fetch.Reset()
	defer fetch.Reset()
	fetch.Extra = http.Header{"Cookie": {"sid=whatever"}}
	rep := &report{}
	watchSession(context.Background(), []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}, "", "", nil, nil, rep, 0)
	if _, _, err := fetch.Do(context.Background(), srv.Client(), srv.URL+"/en/"); err != nil {
		t.Fatalf("the run stopped: %v", err)
	}
	if len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "no page showed the session live") {
		t.Errorf("notes %q", rep.Notes)
	}
}
