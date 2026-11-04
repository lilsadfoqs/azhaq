package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A response ends the session when it expires a cookie the run sends, and
// only then: another cookie, or one set to a value, does not.
func TestClearsSession(t *testing.T) {
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc; theme=dark"}}
	for set, want := range map[string]bool{
		"sid=; Max-Age=0; Path=/":                      true,
		"sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT": true,
		"sid=; Path=/":                                 true,
		"sid=newvalue; Path=/":                         false,
		"other=; Max-Age=0":                            false,
		"theme=light":                                  false,
	} {
		if got := clearsSession(http.Header{"Set-Cookie": {set}}); got != want {
			t.Errorf("%q: %v, want %v", set, got, want)
		}
	}
	Extra = http.Header{"Authorization": {"Bearer x"}}
	if clearsSession(http.Header{"Set-Cookie": {"sid=; Max-Age=0"}}) {
		t.Error("a run with no cookie has none to lose")
	}
}

// A response that gives a cookie the user gave another value asks for a
// check; a response that sets it to the same value, or sets another, does not.
func TestReplacesSession(t *testing.T) {
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc; theme=dark"}}
	for set, want := range map[string]bool{
		"sid=other; Path=/":  true,
		"sid=abc; Path=/":    false,
		"theme=light":        true,
		"other=x":            false,
		"sid=; Max-Age=0":    false,
		"sid=new; Max-Age=0": false,
	} {
		if got := replacesSession(http.Header{"Set-Cookie": {set}}); got != want {
			t.Errorf("%q: %v, want %v", set, got, want)
		}
	}
}

func sessionSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("ok"))
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/to-login":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/logout":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1, Path: "/"})
			_, _ = w.Write([]byte("bye"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A worker keeps no check of its own: it tells the run which GETs it sent
// and whether an answer looked like the end of the session.
func TestRemoteGuardReportsWhatItSaw(t *testing.T) {
	srv := sessionSite(t)
	for path, want := range map[string]SessionReport{
		"/ok":       {},
		"/401":      {Due: true},
		"/to-login": {Due: true},
		"/logout":   {Due: true, EndedBy: "/logout"},
	} {
		Reset()
		Extra = http.Header{"Cookie": {"sid=abc"}}
		WatchRemote(srv.URL+"/login", nil)
		if _, _, err := Do(context.Background(), srv.Client(), srv.URL+path); err != nil {
			t.Fatal(err)
		}
		got := TakeReport()
		if got == nil || len(got.Asked) != 1 || got.Due != want.Due || got.EndedBy != "" && got.EndedBy != srv.URL+want.EndedBy {
			t.Errorf("%s: report %+v, want %+v", path, got, want)
		}
		if TakeReport() != nil {
			t.Errorf("%s: a report is told once", path)
		}
	}
	Reset()
}

// The run counts a worker's requests toward its check, makes the check when
// an answer asked for it, signs in again, and asks again what the workers
// asked since the last good check, and what tasks lent before it asked.
func TestRunChecksForItsWorkers(t *testing.T) {
	srv := sessionSite(t)
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc"}}
	renewed := 0
	// /ok answers 200 with the session; the check is asked without moving.
	WatchSession(Session{Check: srv.URL + "/ok", Want: Print{Status: 200}, Every: 3, Renew: func(context.Context) error {
		renewed++
		SetExtra(http.Header{"Cookie": {"sid=new"}})
		return nil
	}})
	if SessionGen() != 0 {
		t.Fatal("no renewal yet")
	}
	// Two requests are fewer than 3 and nothing asked: no check.
	AbsorbReport(&SessionReport{Asked: []string{"/a"}}, 2, true)
	if err := CheckDue(context.Background()); err != nil || renewed != 0 || SessionGen() != 0 {
		t.Fatalf("early check: %v %d", err, renewed)
	}
	// The check passes (/ok answers 200): nothing is renewed, the stretch is closed.
	AbsorbReport(&SessionReport{Asked: []string{"/b"}}, 1, true)
	if err := CheckDue(context.Background()); err != nil || renewed != 0 || TakeRedo() != nil {
		t.Fatalf("passing check: %v %d", err, renewed)
	}
	// A check that fails signs in again, and the stretch's GETs are asked again.
	WatchSession(Session{Check: srv.URL + "/401", Want: Print{Status: 200}, Every: 100, Renew: func(context.Context) error {
		renewed++
		return nil
	}})
	AbsorbReport(&SessionReport{Asked: []string{srv.URL + "/p", srv.URL + "/q"}, Due: true, EndedBy: srv.URL + "/q"}, 2, true)
	if err := CheckDue(context.Background()); err == nil {
		// the check page still answers 401 after signing in: the run stops
		t.Fatal("a session that does not come back is a failure")
	}
	if renewed != 1 || SessionLost() == nil {
		t.Fatalf("renewed %d, lost %v", renewed, SessionLost())
	}
	// Tasks lent before a renewal are asked again whole.
	Reset()
	Extra = http.Header{"Cookie": {"sid=abc"}}
	WatchSession(Session{Check: srv.URL + "/ok", Want: Print{Status: 200}, Renew: func(context.Context) error { return nil }})
	AbsorbReport(&SessionReport{Asked: []string{srv.URL + "/old"}}, 1, false)
	if redo := TakeRedo(); len(redo) != 1 || redo[0] != srv.URL+"/old" {
		t.Errorf("redo %v", redo)
	}
}

// A renewal is counted, so a worker knows to fetch the new headers.
func TestSessionGenCountsRenewals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "good" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=stale"}}
	n := 0
	WatchSession(Session{Check: srv.URL + "/me", Want: Print{Status: 200}, Every: 1, Renew: func(context.Context) error {
		n++
		SetExtra(http.Header{"Cookie": {"sid=good"}})
		return nil
	}})
	AbsorbReport(&SessionReport{Asked: []string{srv.URL + "/x"}, Due: true}, 1, true)
	if err := CheckDue(context.Background()); err != nil || n != 1 || SessionGen() != 1 {
		t.Fatalf("check %v, renewed %d, gen %d", err, n, SessionGen())
	}
	if redo := TakeRedo(); len(redo) != 1 || redo[0] != srv.URL+"/x" {
		t.Errorf("redo %v", redo)
	}
	if got := strings.Join(ExtraLines(), "|"); got != "Cookie: sid=good" {
		t.Errorf("lines %q", got)
	}
	SetExtraLines([]string{"Cookie: sid=zzz", "X-Token: t"})
	if got := strings.Join(ExtraLines(), "|"); !strings.Contains(got, "Cookie: sid=zzz") || !strings.Contains(got, "X-Token: t") {
		t.Errorf("lines %q", got)
	}
}

// With no check page at the start, a JSON answer that a visitor without the
// session is refused becomes the check; a static page, and a JSON answer
// both get alike, do not.
func TestProbeFindsTheCheckPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch c, _ := r.Cookie("sid"); {
		case r.URL.Path == "/status":
			_, _ = w.Write([]byte(`{"ok":true}`))
		case c == nil:
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte(`{"me":"x"}`))
		}
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=abc"}}
	WatchSession(Session{Every: 1000})
	for _, p := range []string{"/status", "/me"} {
		if _, _, err := Do(context.Background(), srv.Client(), srv.URL+p); err != nil {
			t.Fatal(err)
		}
	}
	page, want := guardP.Load().page()
	if page != srv.URL+"/me" || want.Status != 200 {
		t.Errorf("check page %q answering %v, want /me answering 200", page, want)
	}
}

// While the run signs in again, no other request is sent with the session
// that ended: it waits for the new one. The requests the sign-in makes with
// the context it was given pass.
func TestRequestsWaitForTheNewSessionWhileSigningInAgain(t *testing.T) {
	var mu sync.Mutex
	var seen []string // the cookie of each request, in the order they arrived
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		mu.Lock()
		if r.URL.Path != "/me" {
			seen = append(seen, r.URL.Path+" "+c.Value)
		}
		mu.Unlock()
		if c == nil || c.Value != "new" && r.URL.Path == "/me" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	Reset()
	defer Reset()
	Extra = http.Header{"Cookie": {"sid=old"}}
	inSignIn, release := make(chan struct{}), make(chan struct{})
	WatchSession(Session{Check: srv.URL + "/me", Want: Print{Status: 200}, Every: 1000, Renew: func(ctx context.Context) error {
		close(inSignIn)
		// the sign-in's own request, made with its context, is not held
		if _, _, err := Do(ctx, srv.Client(), srv.URL+"/signin"); err != nil {
			return err
		}
		<-release
		SetExtra(http.Header{"Cookie": {"sid=new"}})
		return nil
	}})
	AbsorbReport(&SessionReport{Due: true}, 1, true)
	checked := make(chan error, 1)
	go func() { checked <- CheckDue(context.Background()) }()
	<-inSignIn
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = Do(context.Background(), srv.Client(), srv.URL+"/other")
		}()
	}
	time.Sleep(150 * time.Millisecond) // long enough for a request that is not held to arrive
	mu.Lock()
	during := append([]string(nil), seen...)
	mu.Unlock()
	close(release)
	if err := <-checked; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if len(during) != 1 || during[0] != "/signin old" {
		t.Errorf("sent while signing in again: %v, want only the sign-in's own request", during)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen[1:] {
		if s != "/other new" {
			t.Errorf("a request went out with the old session: %s (all %v)", s, seen)
		}
	}
}

// A Chrome page's answer that redirects to the sign-in page, or answers
// 401, makes the next request wait for the check, as one of the run's own.
func TestSawAnswerSetsTheCheck(t *testing.T) {
	Reset()
	defer Reset()
	WatchSession(Session{Check: "http://h/me", Want: Print{Status: 200}, Every: 1000, SignIn: "http://h/login.php"})
	g := guardP.Load()
	SawAnswer("http://h/v/1.php", 302, "../other.php")
	if g.due.Load() {
		t.Fatal("a redirect elsewhere set the check")
	}
	SawAnswer("http://h/v/1.php", 302, "../login.php")
	if !g.due.Load() || g.endAns != "http://h/v/1.php" || g.signal != "/v/1.php answered 302 to /login.php" {
		t.Errorf("a redirect to the sign-in page: due %v, first answer %q, signal %q", g.due.Load(), g.endAns, g.signal)
	}
	g.due.Store(false)
	g.endAns, g.signal = "", ""
	SawAnswer("http://h/api", 401, "")
	if !g.due.Load() || g.signal != "/api answered 401" {
		t.Errorf("a 401: due %v, signal %q", g.due.Load(), g.signal)
	}
}
