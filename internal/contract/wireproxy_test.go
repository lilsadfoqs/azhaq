package contract

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// roles asks a role again for the reason when it is refused: that read goes
// through -proxy as every other request of the command, so the proxy and the
// ledger see the same requests.
func TestRolesRefusalReadGoesThroughTheProxy(t *testing.T) {
	l := newLabs(t)
	r := l.Cmd("roles", "-role", "anon", "-role", "alice=Authorization: Bearer t-alice", "-role", "bob=Authorization: Bearer refused",
		"-replay", "-dir", "rd", "-proxy", l.Proxy.URL, "--", "-url", l.Site.URL, "-allow", l.Allow())
	if !strings.Contains(r.Stderr, "role bob was refused wherever a session matters") {
		t.Fatalf("bob was not refused, so no reason was asked for:\n%s", r.Stderr)
	}
	v := newInv(t, "")
	checkRow(t, v, l, row{name: "roles with a refused role", exit: []int{3}, ledgers: []string{"rd/roles.ledger.jsonl"}}, l.sent(r))
	v.Done()
}

// A -proxy that cannot be reached: nothing reached the proxy or the target,
// so nothing was sent. The error names the proxy, the ledger lists the
// request as not sent, and no count of requests holds it.
func TestADeadProxyIsNamedAndNothingIsCountedSent(t *testing.T) {
	l := newLabs(t)
	dead := "http://127.0.0.1:1"
	r := RunRaw(t, l.Dir, nil, "run", "-url", l.Site.URL+"/about", "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-proxy", dead, "-json")
	if r.Code != 3 {
		t.Errorf("exit %d, want 3\n%s", r.Code, r.Stderr)
	}
	if len(r.Summary.Failed) == 0 || r.Summary.Failed[0].Error != "proxy 127.0.0.1:1: connection refused" {
		t.Errorf("failed %+v, want the error `proxy 127.0.0.1:1: connection refused`\n%s", r.Summary.Failed, r.Stderr)
	}
	if r.Summary.Requests != 0 || r.Summary.Cost.Actual.Requests != 0 {
		t.Errorf("the summary says %d requests, the cost %d actual: nothing left", r.Summary.Requests, r.Summary.Cost.Actual.Requests)
	}
	lines := readLedger(t, filepath.Join(l.Dir, "w.db.ledger.jsonl"))
	notSent := 0
	for _, ln := range lines {
		if ln.NotSent {
			notSent++
		}
	}
	if notSent == 0 || ledgerSent(lines).N != 0 {
		t.Errorf("the ledger lists %d lines not sent and %d sent; want some not sent and none sent: %+v", notSent, ledgerSent(lines).N, lines)
	}
	if n := l.Site.Wire.Total() + l.Proxy.Wire.Total(); n != 0 {
		t.Errorf("%d requests reached the site or the proxy", n)
	}
	if res := RunRaw(t, l.Dir, nil, "ledger", "-verify", "w.db.ledger.jsonl"); res.Code != 0 {
		t.Errorf("ledger -verify: exit %d\n%s", res.Code, res.Stderr)
	}
}

// loginSite is a site with a sign-in form (Chrome signs in on it), an API
// that reads a session cookie or a bearer token, and a first session that
// dies after two reads of /api/v1/h*, so that a replay renews it.
type loginSite struct {
	*httptest.Server
	Wire   *Wire // what the site itself saw
	mu     sync.Mutex
	logins int
	first  string
	reads  int
	dead   map[string]bool
}

func newLoginSite(t *testing.T) *loginSite {
	t.Helper()
	s := &loginSite{dead: map[string]bool{}, Wire: newWire()}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Wire.addHTTP(r.Method, s.URL+r.RequestURI)
		sid := ""
		if c, err := r.Cookie("sid"); err == nil {
			sid = c.Value
		}
		s.mu.Lock()
		valid := sid != "" && !s.dead[sid]
		s.mu.Unlock()
		switch p := r.URL.Path; {
		case p == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>shop</title><a href="/api/me">me</a> <a href="/login.php">sign in</a></html>`)
		case p == "/login.php" && r.Method == http.MethodPost:
			s.mu.Lock()
			s.logins++
			sid := fmt.Sprintf("s%d", s.logins)
			if s.first == "" {
				s.first = sid
			}
			s.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
			http.Redirect(w, r, "/", http.StatusFound)
		case p == "/login.php":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>sign in</title><form action="login.php" method="post"><input name="username"><input type="password" name="password"><input type="submit" value="Login"></form></html>`)
		case p == "/favicon.ico":
			http.NotFound(w, r)
		case strings.HasPrefix(p, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			bearer := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer t-")
			if strings.HasPrefix(p, "/api/v1/h") && sid != "" {
				s.mu.Lock()
				if sid == s.first {
					if s.reads++; s.reads > 2 {
						s.dead[sid] = true
						valid = false
					}
				}
				s.mu.Unlock()
			}
			if !valid && !bearer {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"session expired"}`)
				return
			}
			fmt.Fprintf(w, `{"path":%q,"user":"alice"}`, p)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// roles signs a role in with Chrome, has another role refused (so it asks the
// site for the reason), and renews the signed-in role when its session dies
// in the replay: every one of those requests goes through -proxy, so the
// proxy and the ledger see the same.
func TestRolesSignInAndRenewalGoThroughTheProxy(t *testing.T) {
	if _, err := exec.LookPath("google-chrome"); err != nil {
		if _, err := exec.LookPath("chromium"); err != nil {
			t.Skip("no Chrome on this machine")
		}
	}
	l := newLabs(t)
	site := newLoginSite(t)
	host := strings.TrimPrefix(site.URL, "http://")
	var entries [][2]string
	for i := 1; i <= 6; i++ {
		entries = append(entries, [2]string{"GET", fmt.Sprintf("/api/v1/h%d", i)})
	}
	h := l.File("carol.har", har(&Site{Server: site.Server}, entries...))
	r := RunRaw(t, l.Dir, nil, "roles", "-role", "anon", "-role-login", "alice=alice:secret", "-role", "bob=Authorization: Bearer refused",
		"-har", "carol="+h, "-login", site.URL+"/login.php", "-replay", "-canary-every", "2", "-canary", "alice:"+site.URL+"/api/me", "-dir", "rd", "-proxy", l.Proxy.URL, "-json",
		"--", "-url", site.URL+"/", "-allow", host, "-depth", "1", "-no-paths", "-no-favicon")
	if !r.Has || r.Code == 1 {
		t.Skipf("Chrome did not start here: %s", strings.TrimSpace(r.Stderr))
	}
	notes := strings.Join(r.Summary.Notes, "\n")
	for _, want := range []string{"role bob was refused wherever a session matters", "signed in again"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q:\n%s", want, notes)
		}
	}
	site.mu.Lock()
	logins := site.logins
	site.mu.Unlock()
	if logins < 2 {
		t.Errorf("the site saw %d sign-ins: the first, and a renewal, are wanted", logins)
	}
	l.results = append(l.results, r)
	v := newInv(t, "")
	l.Site.Wire = site.Wire // the site the roles ask is not the labs' own
	checkRow(t, v, l, row{name: "roles with sign-in, a refused role and a renewal", writes: true, exit: []int{3}, ledgers: []string{"rd/roles.ledger.jsonl"}}, l.sent(r))
	v.Done()
}
