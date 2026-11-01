package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A -role-login run sends requests of three kinds: the role runs', Chrome's
// sign-in (the page, its assets, the form post) and the replay's. The
// summary, the per-role summaries and the ledger count the same ones.
func TestRolesLoginCountsEveryRequestOfTheSignIn(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	hits := map[string]int{}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		loggedIn := strings.Contains(r.Header.Get("Cookie"), "sid=")
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "index.php", http.StatusFound)
		case "/index.php":
			if !loggedIn {
				http.Redirect(w, r, "login.php", http.StatusFound)
				return
			}
			fmt.Fprint(w, `<html><head><link rel=stylesheet href="/css/main.css"><script src="/js/dvwa.js"></script></head><body><img src="/images/logo.png"><a href="/vulnerabilities/">v</a></body></html>`)
		case "/login.php":
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x", Path: "/"})
			if r.Method == http.MethodPost {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s1", Path: "/"})
				http.Redirect(w, r, "index.php", http.StatusFound)
				return
			}
			fmt.Fprint(w, `<html><head><link rel=stylesheet href="/css/login.css"></head><body><img src="/images/login_logo.png">
<form action="login.php" method=post><input name=username><input type=password name=password><input type=submit name=Login value=Login><input type=hidden name=user_token value=abc></form></body></html>`)
		case "/css/login.css", "/css/main.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `body{margin:0}`)
		case "/js/dvwa.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `window.x=1`)
		case "/images/logo.png", "/images/login_logo.png", "/favicon.ico":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("\x89PNG\r\n\x1a\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	dir := t.TempDir()
	_, errOut, err := captureBoth(t, func() error {
		_, e := captureStdout(t, func() error {
			return cmdRoles([]string{"-dir", dir, "-login", site.URL + "/login.php", "-role", "anon",
				"-role-login", "admin=admin:password", "--", "-url", site.URL + "/", "-no-paths", "-depth", "0", "-allow", strings.TrimPrefix(site.URL, "http://")})
		})
		return e
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	// "azhaq run: … · N requests · …" for each role, "azhaq roles: … · N requests · …" for all.
	count := regexp.MustCompile(`^azhaq (run|roles): .*? · (\d+) requests`)
	var perRole []int
	agg := -1
	for _, l := range strings.Split(errOut, "\n") {
		if m := count.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[2])
			if m[1] == "run" {
				perRole = append(perRole, n)
			} else {
				agg = n
			}
		}
	}
	target := 0
	_ = ledger.Read(filepath.Join(dir, "roles.ledger.jsonl"), func(e ledger.Entry) error {
		if e.Kind != ledger.KindSeal && e.Class != ledger.ClassSource && e.Class != ledger.ClassDNS && e.Class != ledger.ClassOwn {
			target++
		}
		return nil
	})
	mu.Lock()
	served := 0
	for _, n := range hits {
		served += n
	}
	mu.Unlock()
	sum := 0
	for _, n := range perRole {
		sum += n
	}
	if len(perRole) != 2 || agg < 0 {
		t.Fatalf("want one summary per role and one for roles, got %v and %d\n%s", perRole, agg, errOut)
	}
	// The anonymous role's replay of a signed-in page follows a redirect to
	// the sign-in page: one more request than URLs asked.
	if agg != target || agg != served || sum > agg {
		t.Errorf("per role %v, all %d, ledger lines to targets %d, requests the site served %d\n%s", perRole, agg, target, served, errOut)
	}
	if strings.Contains(errOut, "the summary counts") {
		t.Errorf("the ledger check found the summary off\n%s", errOut)
	}
}
