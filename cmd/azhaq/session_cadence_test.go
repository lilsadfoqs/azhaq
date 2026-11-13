package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// The page the session was checked by logs the session out right after its
// first 200; the run's own GET of it is answered with a redirect to the
// sign-in page. That GET went out with the dead session: the summary counts
// it, and does not say that none was sent.
func TestCookieRunCountsTheGETThatRevealedTheEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	var mu sync.Mutex
	live := true
	deadWith := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("PHPSESSID")
		mu.Lock()
		defer mu.Unlock()
		ok := live && c != nil && c.Value == "good"
		if !live && c != nil && r.URL.Path == "/p/" {
			deadWith++
		}
		switch {
		case r.URL.Path == "/login.php":
			fmt.Fprint(w, `<form><input type=password name=p></form>`)
		case r.URL.Path == "/p/" && ok:
			live = false // right after this answer
			fmt.Fprint(w, `<title>page</title>`)
		case r.URL.Path == "/p/":
			w.Header().Set("Location", "login.php")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/p/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths",
		"-no-favicon", "-no-tech", "-cookie", "PHPSESSID=good", "-rate", "100", "-db", "s.db", "-ledger", "off", "-json")
	if code != exitPartial {
		t.Fatalf("exit %d, want 3:\n%s", code, errOut)
	}
	loss, _ := sumMap(t, errOut)["session_lost"].(map[string]any)
	if loss == nil {
		t.Fatalf("no session_lost in the summary:\n%s", errOut)
	}
	asked, _ := loss["asked_since_good_check"].(float64)
	inFlight, _ := loss["in_flight"].(float64)
	mu.Lock()
	defer mu.Unlock()
	if deadWith < 2 { // the run's GET, and the check asked again with the session
		t.Fatalf("the app saw %d requests of /p/ with the dead session: the test shows nothing", deadWith)
	}
	if asked+inFlight < 1 {
		t.Errorf("session_lost %v says no request went out without the session, but the run's GET did", loss)
	}
}
