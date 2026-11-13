package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// cadenceApp answers 200 to a live session on /me and every other path, a
// redirect to /login to anyone else on /me, and 404 elsewhere once the session
// ended: a logout that says nothing on the paths a sweep asks.
type cadenceApp struct {
	mu   sync.Mutex
	live bool
	srv  *httptest.Server
	log  []string // "path live|dead with|without the session"
}

func newCadenceApp(t *testing.T) *cadenceApp {
	a := &cadenceApp{live: true}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		a.mu.Lock()
		state := "dead"
		if a.live {
			state = "live"
		}
		with := "without"
		if c != nil {
			with = "with"
		}
		a.log = append(a.log, r.URL.Path+" "+state+" "+with)
		ok := a.live && c != nil
		a.mu.Unlock()
		switch {
		case r.URL.Path == "/login":
			_, _ = w.Write([]byte("sign in"))
		case r.URL.Path == "/me" && !ok:
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/me" || ok:
			_, _ = w.Write([]byte("page"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *cadenceApp) logout() {
	a.mu.Lock()
	a.live = false
	a.mu.Unlock()
}

// reached counts the requests whose path starts with prefix.
func (a *cadenceApp) reached(prefix string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// deadWith counts the requests of path that reached the app with the session after it ended.
func (a *cadenceApp) deadWith(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.log {
		if l == path+" dead with" {
			n++
		}
	}
	return n
}

func (a *cadenceApp) checks() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, l := range a.log {
		if l == "/me live with" || l == "/me dead with" {
			n++
		}
	}
	return n
}

func startCadence(t *testing.T, a *cadenceApp, s Session) *sessionGuard {
	t.Helper()
	Reset()
	t.Cleanup(Reset)
	Extra = http.Header{"Cookie": {"sid=good"}}
	s.Check, s.Want, s.SignIn = a.srv.URL+"/me", Print{Status: 200}, a.srv.URL+"/login"
	WatchSession(s)
	return guardP.Load()
}

// The GET whose answer was the first sign of the end is sent with the
// session that ended: the failure counts it, even though its Do has not
// returned when the check runs on its redirect hop.
func TestFailureCountsTheRequestThatRevealedTheEnd(t *testing.T) {
	a := newCadenceApp(t)
	startCadence(t, a, Session{Every: 1000})
	a.logout() // the session ended after the page that told the check was live
	// The check runs on the redirect hop; the hop is refused, the GET's own
	// answer is returned, and every request after it is refused.
	_, _, _ = Do(context.Background(), a.srv.Client(), a.srv.URL+"/me")
	var sl *neterr.SessionLost
	if !errors.As(SessionLost(), &sl) {
		t.Fatalf("no session failure: %v", SessionLost())
	}
	if sl.Asked != 1 || len(sl.InFlight) != 0 {
		t.Errorf("asked %d, in flight %d: want the request that got the redirect counted (1, 0): %s", sl.Asked, len(sl.InFlight), sl.Msg)
	}
	if a.deadWith("/me") < 1 {
		t.Error("the run's own GET did not reach the app with the dead session: the test shows nothing")
	}
}
