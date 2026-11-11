package main

import (
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
