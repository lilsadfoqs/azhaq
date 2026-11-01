package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
	watchSession(ctx, []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}}, "", "", nil, rep)
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
