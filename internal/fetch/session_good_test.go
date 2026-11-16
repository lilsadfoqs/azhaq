package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// goodSite is a site with a public page and protected /app pages: with the
// session ended they answer as end says, a redirect to a page with a password
// form, a plain redirect, a 401 or a 403.
type goodSite struct {
	live atomic.Bool
	end  string
	mu   sync.Mutex
	sent []string
	srv  *httptest.Server
}

func newGoodSite(t *testing.T, end string) *goodSite {
	s := &goodSite{end: end}
	s.live.Store(true)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.sent = append(s.sent, r.URL.Path)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/login":
			_, _ = w.Write([]byte(`<form><input type="password" name=p></form>`))
		case r.URL.Path == "/en/":
			_, _ = w.Write([]byte(`<title>Welcome</title>`))
		case !strings.HasPrefix(r.URL.Path, "/app") || s.live.Load():
			_, _ = w.Write([]byte(`<title>page</title>`))
		case s.end == "401":
			w.WriteHeader(http.StatusUnauthorized)
		case s.end == "403":
			w.WriteHeader(http.StatusForbidden)
		case s.end == "plain redirect":
			http.Redirect(w, r, "/en/", http.StatusFound)
		default:
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	Reset()
	t.Cleanup(Reset)
	Extra = http.Header{"Cookie": {"sid=abc"}}
	return s
}

func (s *goodSite) get(p string) error {
	_, _, err := Do(context.Background(), s.srv.Client(), s.srv.URL+p)
	return err
}

func (s *goodSite) count(p string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, x := range s.sent {
		if x == p {
			n++
		}
	}
	return n
}

// With no page that differs signed in and out, a page that answered 200 with
// the session and now answers a redirect to a form that takes a password, a
// 401 or a 403 is the end of the session: the next request is refused, the
// page is the check, and the failure counts the GETs asked since that page
// answered.
func TestAPageThatAnsweredWithTheSessionAndNowTurnsAwayEndsIt(t *testing.T) {
	for _, end := range []string{"redirect to a password form", "401", "403"} {
		t.Run(end, func(t *testing.T) {
			s := newGoodSite(t, end)
			WatchSession(Session{Every: 1000, Why: "given with -cookie"})
			for _, p := range []string{"/", "/en/", "/app/a"} {
				if err := s.get(p); err != nil {
					t.Fatal(err)
				}
			}
			s.live.Store(false)
			if err := s.get("/app/b"); err != nil {
				t.Fatalf("the answer that looked like the end is the run's own: %v", err)
			}
			before := s.count("/app/c")
			err := s.get("/app/c")
			var sl *neterr.SessionLost
			if !errors.As(err, &sl) {
				t.Fatalf("the next request was not refused: %v", err)
			}
			if s.count("/app/c") != before {
				t.Error("a request went out after the end was measured")
			}
			if page, want := guardP.Load().page(); page != s.srv.URL+"/app/a" || want.Status != 200 {
				t.Errorf("check page %q answering %v, want /app/a answering 200", page, want)
			}
			if !strings.Contains(sl.Msg, "/app/a answered") || !strings.Contains(sl.Msg, "where it answered 200 with the session") {
				t.Errorf("the failure does not say what was measured: %s", sl.Msg)
			}
			if sl.Asked != 1 { // /app/b: / and /en/ were answered before /app/a held
				t.Errorf("asked_since_good_check %d, want 1", sl.Asked)
			}
		})
	}
}

// A page that never answered 200 with the session, a redirect to a page that
// takes no password, and a page that still answers 200, are no end.
func TestAnswersThatAreNotTheEndOfTheSessionStopNothing(t *testing.T) {
	t.Run("always redirected", func(t *testing.T) {
		s := newGoodSite(t, "redirect to a password form")
		s.live.Store(false) // the session never held on /app
		WatchSession(Session{Every: 1000})
		for _, p := range []string{"/", "/app/a", "/app/b", "/app/c", "/app/d", "/app/e", "/"} {
			if err := s.get(p); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
		}
	})
	t.Run("redirect to a page without a password form", func(t *testing.T) {
		s := newGoodSite(t, "plain redirect")
		WatchSession(Session{Every: 1000})
		for _, p := range []string{"/", "/app/a"} {
			if err := s.get(p); err != nil {
				t.Fatal(err)
			}
		}
		s.live.Store(false)
		for _, p := range []string{"/app/b", "/app/c", "/app/d"} {
			if err := s.get(p); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
		}
	})
}

// Without an answer that looks like the end, the check owed every
// -session-every requests asks one kept page, the one asked again longest
// ago, so that a session that ended with no sign of it is found.
func TestACheckOwedAsksTheKeptPagesInTurn(t *testing.T) {
	s := newGoodSite(t, "401")
	WatchSession(Session{Every: 1})
	if err := s.get("/app/a"); err != nil {
		t.Fatal(err)
	}
	s.live.Store(false)
	var lost error
	for _, p := range []string{"/en/", "/", "/en/", "/"} {
		if lost = s.get(p); lost != nil {
			break
		}
	}
	if !errors.Is(lost, neterr.ErrSessionLost) {
		t.Fatalf("the ended session was not found by the checks owed: %v", lost)
	}
}

// A 403 or a redirect that is the page's own answer costs a check the first
// 3 times, then each time its count doubles, not each time.
func TestARepeatedAnswerIsNotCheckedEachTime(t *testing.T) {
	s := newGoodSite(t, "403")
	WatchSession(Session{Every: 1000})
	if err := s.get("/"); err != nil {
		t.Fatal(err)
	}
	s.live.Store(false) // /app answers 403 to everyone: "/" still holds, and no page of /app answered 200
	for i := range 40 {
		if err := s.get("/app/p" + string(rune('a'+i%26)) + string(rune('a'+i/26))); err != nil {
			t.Fatal(err)
		}
	}
	// "/" is asked once as a request of the run, then once per check: 1, 2, 3, 4, 8, 16, 32.
	if n := s.count("/"); n > 8 {
		t.Errorf("/ was asked %d times for 40 alike answers, want a few", n)
	}
}

// With -login the run signs in again, as for any failed check, and goes on.
func TestAMeasuredEndIsRenewedWithALogin(t *testing.T) {
	s := newGoodSite(t, "redirect to a password form")
	renewals := 0
	WatchSession(Session{Every: 1000, Renew: func(context.Context) error { renewals++; s.live.Store(true); return nil }})
	for _, p := range []string{"/", "/app/a"} {
		if err := s.get(p); err != nil {
			t.Fatal(err)
		}
	}
	s.live.Store(false)
	for _, p := range []string{"/app/b", "/app/c"} {
		if err := s.get(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if renewals != 1 {
		t.Fatalf("signed in %d times, want once", renewals)
	}
}
