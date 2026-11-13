package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
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

// A logout that answers 404 on every path is no telltale answer: the check
// before a stage that sends many requests finds it, and the stage's requests
// are refused, not sent with the dead session.
func TestStageCheckStopsASweepAfterAQuietLogout(t *testing.T) {
	a := newCadenceApp(t)
	startCadence(t, a, Session{Every: 1000})
	ctx := context.Background()
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+p); err != nil {
			t.Fatal(err)
		}
	}
	a.logout()
	err := StageCheck(ctx, 0)
	if !errors.Is(err, neterr.ErrSessionLost) {
		t.Fatalf("the check before the stage found nothing: %v", err)
	}
	for i := 0; i < 30; i++ {
		if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+"/g"+string(rune('a'+i%26))+string(rune('a'+i/26))); !errors.Is(err, neterr.ErrSessionLost) {
			t.Fatalf("a sweep request %d was not refused: %v", i, err)
		}
	}
	if n := a.reached("/g"); n != 0 {
		t.Errorf("%d sweep requests reached the app after the check found the session ended", n)
	}
	if n := a.checks(); n != 1 {
		t.Errorf("the check page was asked %d times with the session, want 1", n)
	}
}

// A check is skipped when only the check's own few requests passed since the
// last good check, and when the stage sends no more than a check does.
func TestStageCheckSkipsWhenACheckHeldJustBefore(t *testing.T) {
	a := newCadenceApp(t)
	startCadence(t, a, Session{Every: 1000})
	ctx := context.Background()
	if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	a.logout()
	if err := StageCheck(ctx, 0); err != nil || a.checks() != 0 {
		t.Errorf("one request after a good check: %v, %d checks, want none", err, a.checks())
	}
	for _, p := range []string{"/b", "/c", "/d"} {
		_, _, _ = Do(ctx, a.srv.Client(), a.srv.URL+p)
	}
	if err := StageCheck(ctx, 2); err != nil || a.checks() != 0 {
		t.Errorf("a stage of 2 requests: %v, %d checks, want none", err, a.checks())
	}
	if err := StageCheck(ctx, 3); !errors.Is(err, neterr.ErrSessionLost) || a.checks() != 1 {
		t.Errorf("a stage of 3 requests after 4: %v, %d checks, want the check and the failure", err, a.checks())
	}
}

// After Window of wall time since the last good check, the next request that
// is about to go out makes the check first; passing time alone sends nothing.
func TestTimeCheckRunsAtTheNextRequestAfterTheWindow(t *testing.T) {
	a := newCadenceApp(t)
	g := startCadence(t, a, Session{Every: 1000})
	var mu sync.Mutex
	at := time.Now()
	g.clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return at }
	g.stamp()
	advance := func(d time.Duration) { mu.Lock(); at = at.Add(d); mu.Unlock() }
	ctx := context.Background()
	if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	a.logout()
	advance(9 * time.Second)
	if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+"/b"); err != nil {
		t.Fatalf("a request 9 s after the last good check was refused: %v", err)
	}
	if a.deadWith("/b") != 1 || a.checks() != 0 {
		t.Fatalf("/b dead with session %d times, %d checks: want it sent and no check yet", a.deadWith("/b"), a.checks())
	}
	advance(2 * time.Second) // 11 s: nothing is sent while no request is made
	if a.checks() != 0 {
		t.Fatal("a check ran with no request about to go out")
	}
	if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+"/c"); !errors.Is(err, neterr.ErrSessionLost) {
		t.Fatalf("the request after the window was not refused: %v", err)
	}
	if a.deadWith("/c") != 0 || a.checks() != 1 {
		t.Errorf("/c reached the app %d times, %d checks: want the check only", a.deadWith("/c"), a.checks())
	}
}

// A check that holds starts a new window: the next one is 10 s later, not
// at every request after the first window.
func TestTimeCheckThatHoldsStartsANewWindow(t *testing.T) {
	a := newCadenceApp(t)
	g := startCadence(t, a, Session{Every: 1000})
	var mu sync.Mutex
	at := time.Now()
	g.clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return at }
	g.stamp()
	ctx := context.Background()
	mu.Lock()
	at = at.Add(10 * time.Second)
	mu.Unlock()
	for _, p := range []string{"/a", "/b", "/c"} {
		if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+p); err != nil {
			t.Fatal(err)
		}
	}
	if a.checks() != 1 {
		t.Errorf("%d checks in the window, want 1 (at the first request after 10 s)", a.checks())
	}
	mu.Lock()
	at = at.Add(10 * time.Second)
	mu.Unlock()
	_, _, _ = Do(ctx, a.srv.Client(), a.srv.URL+"/d")
	if a.checks() != 2 {
		t.Errorf("%d checks after the next window, want 2", a.checks())
	}
}

// With Every 1 the check is made before every request: the first request
// after the session ended is refused, not sent.
func TestEveryOneChecksBeforeEveryRequest(t *testing.T) {
	a := newCadenceApp(t)
	startCadence(t, a, Session{Every: 1})
	ctx := context.Background()
	before := egress.Sent()
	for _, p := range []string{"/a", "/b", "/c"} {
		if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+p); err != nil {
			t.Fatal(err)
		}
	}
	if a.checks() != 3 {
		t.Errorf("%d checks before 3 requests, want 3", a.checks())
	}
	if n := egress.Sent() - before; n != 6 {
		t.Errorf("%d requests counted for 3 requests and 3 checks, want 6: a check that holds is one request, counted", n)
	}
	a.logout()
	if _, _, err := Do(ctx, a.srv.Client(), a.srv.URL+"/d"); !errors.Is(err, neterr.ErrSessionLost) {
		t.Fatalf("the request after the logout was not refused: %v", err)
	}
	if a.deadWith("/d") != 0 {
		t.Errorf("/d reached the app with the dead session")
	}
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
