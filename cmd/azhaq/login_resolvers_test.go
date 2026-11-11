package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// The sign-in resolves names as the run's requests do: a name only the
// resolvers given with -resolvers answer is reached by Chrome too.
func TestLoginUsesTheRunsResolvers(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	app := &dvwaSessions{live: map[string]int{}, dead: map[string]bool{}, late: map[string][]string{}}
	srv := httptest.NewServer(app.handler())
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var asked atomic.Int64
	zone := serveCountingZone(t, &asked, map[string]string{"app.lab.internal": "127.0.0.1"})
	site := "http://app.lab.internal:" + u.Port()
	_, errOut, code := cli(t, "run", "-url", site+"/", "-login", site+"/login.php", "-login-user", "admin", "-login-pass", "password",
		"-resolvers", zone, "-allow", "app.lab.internal", "-sources", "none", "-no-paths",
		"-db", filepath.Join(t.TempDir(), "l.db"), "-json")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	app.mu.Lock()
	signedIn := app.next
	app.mu.Unlock()
	if signedIn != 1 {
		t.Errorf("the app saw %d sign-ins, want 1", signedIn)
	}
	if asked.Load() == 0 {
		t.Error("the -resolvers were never asked")
	}
}

// The requests roles sends between the runs (the replay) reach a name only
// the runs' -resolvers answer, as the runs' own requests do.
func TestRolesReplayUsesTheRunsResolvers(t *testing.T) {
	var anonSecret atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Header.Get("Authorization") != "" {
			fmt.Fprint(w, `<html><body><a href="/secret">mine</a></body></html>`)
			return
		}
		fmt.Fprint(w, `<html><body>welcome</body></html>`)
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			anonSecret.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"owner":"alice","note":"hello"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var asked atomic.Int64
	zone := serveCountingZone(t, &asked, map[string]string{"app.lab.internal": "127.0.0.1"})
	site := "http://app.lab.internal:" + u.Port()
	_, errOut, code := cli(t, "roles", "-dir", t.TempDir(), "-role", "anon", "-role", "alice=Authorization: Bearer a1", "-json", "--",
		"-url", site+"/", "-resolvers", zone, "-allow", "app.lab.internal", "-sources", "none", "-no-paths")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if anonSecret.Load() == 0 {
		t.Errorf("the replay never asked /secret without a session: %s", errOut)
	}
}
