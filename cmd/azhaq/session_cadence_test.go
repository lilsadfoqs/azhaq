package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/collectors"
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

// -session-every N sets how many requests pass between checks, and a value
// under 1 is a usage error. With 1 the check is made before every request:
// a logout that no answer shows is found at the next request, so no page of
// the run is asked with the dead session; with the default, the pages that
// follow it are.
func TestRunSessionEveryChecksMoreOften(t *testing.T) {
	serve := func(t *testing.T) (*httptest.Server, func() (deadPages int)) {
		var mu sync.Mutex
		live, pages, dead := true, 0, 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, _ := r.Cookie("sid")
			mu.Lock()
			defer mu.Unlock()
			if r.URL.Path != "/" && r.URL.Path != "/login" {
				pages++
				if pages == 3 {
					live = false // a quiet logout: this page answers 200 as usual
					fmt.Fprint(w, "<title>page</title>")
					return
				}
				if !live && c != nil {
					dead++
				}
			}
			switch {
			case r.URL.Path == "/login":
				fmt.Fprint(w, `<form><input type=password name=p></form>`)
			case r.URL.Path == "/" && (!live || c == nil):
				w.Header().Set("Location", "/login")
				w.WriteHeader(http.StatusFound)
			case r.URL.Path == "/":
				fmt.Fprint(w, `<title>home</title>`)
				for _, p := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
					fmt.Fprintf(w, `<a href="/%s">%s</a>`, p, p)
				}
			case !live:
				http.NotFound(w, r)
			default:
				fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
			}
		}))
		t.Cleanup(srv.Close)
		return srv, func() int { mu.Lock(); defer mu.Unlock(); return dead }
	}
	args := func(url string, extra ...string) []string {
		return append([]string{"run", "-url", url, "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths", "-no-favicon", "-no-tech",
			"-cookie", "sid=good", "-parallel", "1", "-db", "s.db", "-ledger", "off", "-json"}, extra...)
	}
	t.Run("default", func(t *testing.T) {
		t.Chdir(t.TempDir())
		srv, dead := serve(t)
		_, errOut, code := cli(t, args(srv.URL+"/")...)
		if code != exitPartial || dead() == 0 {
			t.Errorf("exit %d, %d pages asked with the dead session: want the failure at the end check and some pages sent meanwhile\n%s", code, dead(), errOut)
		}
	})
	t.Run("every 1", func(t *testing.T) {
		t.Chdir(t.TempDir())
		srv, dead := serve(t)
		_, errOut, code := cli(t, args(srv.URL+"/", "-session-every", "1")...)
		if code != exitPartial || dead() != 0 {
			t.Errorf("exit %d, %d pages asked with the dead session, want the failure and none\n%s", code, dead(), errOut)
		}
	})
	t.Run("under 1 is a usage error", func(t *testing.T) {
		t.Chdir(t.TempDir())
		for _, v := range []string{"0", "-3"} {
			_, errOut, code := cli(t, "run", "-url", "http://127.0.0.1:9/", "-allow", "127.0.0.1", "-session-every", v, "-db", "s.db")
			if code != exitUsage || !strings.Contains(errOut, "-session-every") {
				t.Errorf("-session-every %s: exit %d\n%s", v, code, errOut)
			}
		}
	})
}

// The collectors whose task sends many requests are marked: a signed-in run
// checks its session before each (the path sweep, -dirs, -params, the page
// loads of -screenshots and -browser). Their one-request siblings are not.
func TestStageCollectorsAreTheOnesThatSendManyRequests(t *testing.T) {
	cat := catalog.New()
	collectors.RegisterAll(cat, nil)
	for name, want := range map[string]bool{
		"azhaq-paths": true, "azhaq-dirs": true, "azhaq-params": true, "azhaq-shots": true, "azhaq-render": true,
		"azhaq-http": false, "azhaq-crawl": false, "azhaq-js": false,
	} {
		col, ok := cat.Get(name)
		if !ok {
			t.Fatalf("no collector %s", name)
		}
		if got := catalog.InfoOf(col).Stage; got != want {
			t.Errorf("%s: stage %v, want %v", name, got, want)
		}
	}
}
