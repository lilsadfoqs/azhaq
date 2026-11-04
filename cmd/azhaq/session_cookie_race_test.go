package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A -cookie run, requests in parallel: /logout revokes the session and
// answers with a Set-Cookie that clears it, while a JSON route asked at the
// same time is still being answered. When that answer is read the run knows
// the session ended, so it must not measure it without the session: no
// request reaches the server without the cookie once it was revoked.
func TestCookieRunSendsNothingWithoutItsSessionAfterALogout(t *testing.T) {
	t.Chdir(t.TempDir())
	var mu sync.Mutex
	revoked := false
	var revokedAt time.Time
	type req struct {
		path   string
		cookie bool
		at     time.Time
	}
	var log []req
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		mu.Lock()
		log = append(log, req{r.URL.Path, c != nil, time.Now()})
		wasRevoked := revoked
		if r.URL.Path == "/logout" && c != nil && !revoked {
			revoked, revokedAt = true, time.Now()
		}
		mu.Unlock()
		if c != nil && (wasRevoked || r.URL.Path == "/logout") {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
			if wasRevoked {
				http.Error(w, "session ended", http.StatusUnauthorized)
				return
			}
		}
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<title>home</title><a href="/logout">out</a> <a href="/data.json">d</a> <a href="/about">a</a>`)
		case "/data.json":
			time.Sleep(300 * time.Millisecond) // answered after the logout's answer was read
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
		}
	}))
	defer srv.Close()
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths",
			"-no-favicon", "-no-tech", "-cookie", "sid=good", "-parallel", "8", "-db", "s.db", "-ledger", "off", "-json", "-send-state-changing"})
	})
	if exitCode(err) != exitPartial || !strings.Contains(errOut, neterr.ErrSessionLost.Error()) {
		t.Fatalf("exit %d, the session ended is not said:\n%s", exitCode(err), errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	if revokedAt.IsZero() {
		t.Fatal("the session was never revoked: /logout was not asked")
	}
	for _, q := range log {
		if !q.cookie && q.at.After(revokedAt) {
			t.Errorf("GET %s reached the server without the session after it was revoked", q.path)
		}
	}
}

// The logout is revoked on arrival and answers late, while a JSON route
// answers in between: the run's measurement of that route without the
// session would arrive after the revocation, with the logout still in the
// air. The measurement waits for the logout's answer instead, which ends
// the session, and then is not made.
func TestSessionMeasureWaitsForRequestsInTheAir(t *testing.T) {
	t.Chdir(t.TempDir())
	var mu sync.Mutex
	var revokedAt time.Time
	revoked := make(chan struct{})
	type req struct {
		path   string
		cookie bool
		at     time.Time
	}
	var log []req
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		mu.Lock()
		log = append(log, req{r.URL.Path, c != nil, time.Now()})
		if r.URL.Path == "/logout" && revokedAt.IsZero() {
			revokedAt = time.Now()
			close(revoked)
		}
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<title>home</title><a href="/logout">out</a> <a href="/data.json">d</a>`)
		case "/logout":
			time.Sleep(400 * time.Millisecond) // revoked on arrival, answered late
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
			fmt.Fprint(w, "<title>bye</title>")
		case "/data.json":
			select {
			case <-revoked:
				time.Sleep(100 * time.Millisecond)
			case <-time.After(2 * time.Second):
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
		}
	}))
	defer srv.Close()
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths",
			"-no-favicon", "-no-tech", "-cookie", "sid=good", "-parallel", "8", "-db", "s.db", "-ledger", "off", "-json", "-send-state-changing"})
	})
	if exitCode(err) != exitPartial || !strings.Contains(errOut, neterr.ErrSessionLost.Error()) {
		t.Fatalf("exit %d, the session ended is not said:\n%s", exitCode(err), errOut)
	}
	mu.Lock()
	defer mu.Unlock()
	if revokedAt.IsZero() {
		t.Fatal("/logout was not asked")
	}
	for _, q := range log {
		if !q.cookie && q.at.After(revokedAt) {
			t.Errorf("GET %s reached the server without the session after it was revoked", q.path)
		}
	}
}
