package verify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// noFollowDoer answers a redirect with the redirect itself, as the run's
// target client does; it counts the requests Spend was asked for.
func noFollowDoer() (HTTPDoer, func() int) {
	var mu sync.Mutex
	n := 0
	return HTTPDoer{
		Client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Spend:  func(context.Context) error { mu.Lock(); n++; mu.Unlock(); return nil },
	}, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

func catalogEntry(t *testing.T, id string) DefaultLogin {
	t.Helper()
	for _, lg := range DefaultLogins() {
		if lg.ID == id {
			return lg
		}
	}
	t.Fatalf("no catalog entry %s", id)
	return DefaultLogin{}
}

// credSeen records which credentials reached a fixture, under a mutex: the
// handler runs on the server's goroutines.
type credSeen struct {
	mu    sync.Mutex
	pairs []string
}

func (c *credSeen) add(s string) {
	c.mu.Lock()
	c.pairs = append(c.pairs, s)
	c.mu.Unlock()
}

func (c *credSeen) has(s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.pairs {
		if p == s {
			return true
		}
	}
	return false
}

// A message-broker console whose /admin/ is public and whose password is not
// the default (#548): the one page that answers 200 to all proves nothing.
func TestPublicConsolePageWithAChangedPasswordIsNotProved(t *testing.T) {
	var seen credSeen
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		seen.add(fmt.Sprintf("%s %s:%s", r.URL.Path, u, p))
		switch {
		case r.URL.Path == "/admin/":
			fmt.Fprint(w, `<html><title>Apache ActiveMQ Console</title>Welcome to the Apache ActiveMQ Console</html>`)
		case strings.HasSuffix(r.URL.Path, ".jsp") && ok && u == "admin" && p == "S3cr3t-changed":
			fmt.Fprint(w, `<html><title>Queues</title>queues</html>`)
		default:
			w.WriteHeader(401)
		}
	})
	d, _ := noFollowDoer()
	// The entry as it was: the public page and a rule it meets.
	old := catalogEntry(t, "activemq-admin-admin")
	old.Path, old.Success = "/admin/", basicMarker("activemq", "<html")
	out, err := old.Attempt(context.Background(), d, origin)
	if err != nil {
		t.Fatal(err)
	}
	if out.Success || out.Proof != nil {
		t.Fatalf("a public page was proved: %+v", out)
	}
	if !strings.Contains(out.Note, "answers the same without a credential") || !strings.Contains(out.Note, "was not proved") {
		t.Errorf("note %q", out.Note)
	}
	if seen.has("/admin/ admin:admin") {
		t.Error("the published pair was sent to a page open to all")
	}
	// The catalog's entry now asks a gated page, which refuses the pair.
	lg := catalogEntry(t, "activemq-admin-admin")
	if lg.Path == "/admin/" {
		t.Fatalf("the entry still asks the public page %s", lg.Path)
	}
	_, out, _, err = AttemptLogins(context.Background(), d, origin, []DefaultLogin{lg})
	if err != nil || out.Success {
		t.Fatalf("out %+v err %v", out, err)
	}
}

// The same console with the default password: the gated page takes the pair,
// the controls are refused, and the proof shows both.
func TestGatedConsoleWithTheDefaultPairIsProvedAgainstItsControls(t *testing.T) {
	var seen credSeen
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		seen.add(fmt.Sprintf("%s %s", r.URL.Path, map[bool]string{true: "auth", false: "none"}[ok]))
		switch {
		case r.URL.Path == "/admin/":
			fmt.Fprint(w, `<html><title>Apache ActiveMQ Console</title></html>`)
		case strings.HasSuffix(r.URL.Path, ".jsp") && ok && u == "admin" && p == "admin":
			fmt.Fprint(w, `<html><title>Queues</title>queues</html>`)
		default:
			w.WriteHeader(401)
		}
	})
	d, count := noFollowDoer()
	lg := catalogEntry(t, "activemq-admin-admin")
	_, out, _, err := AttemptLogins(context.Background(), d, origin, []DefaultLogin{lg})
	if err != nil || !out.Success {
		t.Fatalf("out %+v err %v", out, err)
	}
	if count() != 3 {
		t.Errorf("%d requests, want the two controls and the pair", count())
	}
	const want = "no credential: 401; wrong pair: 401; the published pair (admin): 200 + marker"
	if !strings.Contains(out.Excerpt, want) || !strings.Contains(out.Proof.Excerpt, want) || out.Controls != want {
		t.Errorf("controls not in the evidence: %q / %q", out.Excerpt, out.Proof.Excerpt)
	}
	cmd := out.Proof.Reproduce
	if strings.Count(cmd, "curl ") != 3 || !strings.Contains(cmd, "-u 'admin' ") || strings.Contains(cmd, ":admin'") && strings.Contains(cmd, "admin:admin") {
		t.Errorf("reproduce shows %q", cmd)
	}
	if !strings.Contains(cmd, "no credential") || !strings.Contains(cmd, "wrong pair") {
		t.Errorf("reproduce does not name its controls: %q", cmd)
	}
	for _, s := range []string{out.Request, out.Excerpt, out.Proof.Excerpt, cmd} {
		if strings.Contains(s, "admin:admin") {
			t.Errorf("the pair is in %q", s)
		}
	}
}

// A server that takes any credential at all, and refuses only none: the pair
// is no better than a wrong one, so nothing is proved.
func TestAServerThatTakesAnyCredentialProvesNothing(t *testing.T) {
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			fmt.Fprint(w, `queues`)
			return
		}
		w.WriteHeader(401)
	})
	d, _ := noFollowDoer()
	out, err := basicEntry("/admin/queues.jsp", basicMarker("queues")).Attempt(context.Background(), d, origin)
	if err != nil || out.Success || !strings.Contains(out.Note, "with a wrong credential") {
		t.Fatalf("out %+v err %v", out, err)
	}
}

// A rule the controls meet as well as the pair is not a rule: the controls'
// own answers decide, whatever the rule says.
func TestControlOnAnotherStatusClassOrMarkerIsMeasurable(t *testing.T) {
	// Pair 200 + marker; the wrong credential 403 + the marker's page: the
	// status class differs even though the rule is only the marker.
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		switch {
		case !ok:
			w.WriteHeader(401)
		case u == "user" && p == "SuperSecretDefault1":
			fmt.Fprint(w, "ok")
		default:
			w.WriteHeader(403)
			fmt.Fprint(w, "ok")
		}
	})
	d, _ := noFollowDoer()
	out, err := basicEntry("/x", func(_ int, body []byte) bool { return strings.Contains(string(body), "ok") }).Attempt(context.Background(), d, origin)
	if err != nil || !out.Success || !strings.Contains(out.Controls, "wrong pair: 403") {
		t.Fatalf("out %+v err %v", out, err)
	}
}

// A form login whose refusal redirects as well: success is judged against
// the wrong-credential control, by where the redirect goes (Rundeck).
func TestFormLoginThatRedirectsEitherWayIsProvedOnlyByADifferentTarget(t *testing.T) {
	rundeck := catalogEntry(t, "rundeck-admin-admin")
	serve := func(accept bool, good string) func(n int, w http.ResponseWriter, r *http.Request) {
		return func(n int, w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			to := "/user/error"
			if accept && r.Form.Get("j_username") == "admin" && r.Form.Get("j_password") == "admin" {
				to = good
			}
			w.Header().Set("Location", to)
			w.WriteHeader(302)
		}
	}
	d, _ := noFollowDoer()
	t.Run("the pair lands elsewhere: proved", func(t *testing.T) {
		origin, _ := newFixture(t, serve(true, "/menu/home"))
		out, err := rundeck.Attempt(context.Background(), d, origin)
		if err != nil || !out.Success {
			t.Fatalf("out %+v err %v", out, err)
		}
		const want = "no credential: 302 to /user/error; wrong pair: 302 to /user/error; the published pair (admin): 302 to /menu/home"
		if out.Controls != want {
			t.Errorf("controls %q", out.Controls)
		}
	})
	t.Run("every sign-in lands on the error page: not proved", func(t *testing.T) {
		origin, _ := newFixture(t, serve(false, ""))
		out, err := rundeck.Attempt(context.Background(), d, origin)
		if err != nil || out.Success || out.Note == "" {
			t.Fatalf("a refused sign-in was proved: %+v err %v", out, err)
		}
	})
	t.Run("every sign-in lands on the home page: not proved", func(t *testing.T) {
		origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/menu/home")
			w.WriteHeader(302)
		})
		out, err := rundeck.Attempt(context.Background(), d, origin)
		if err != nil || out.Success {
			t.Fatalf("a login that takes anything was proved: %+v err %v", out, err)
		}
	})
	t.Run("OpenNMS: the error page carries a query, the pair does not", func(t *testing.T) {
		on := catalogEntry(t, "opennms-admin-admin")
		origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			to := "/opennms/login.jsp?login_error=1"
			if r.Form.Get("j_username") == "admin" && r.Form.Get("j_password") == "admin" {
				to = "/opennms/index.jsp"
			}
			w.Header().Set("Location", to)
			w.WriteHeader(302)
		})
		out, err := on.Attempt(context.Background(), d, origin)
		if err != nil || !out.Success {
			t.Fatalf("out %+v err %v", out, err)
		}
	})
	t.Run("same target, a session cookie only the pair gets: proved", func(t *testing.T) {
		origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			if r.Form.Get("j_username") == "admin" && r.Form.Get("j_password") == "admin" {
				http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: "x"})
			}
			w.Header().Set("Location", "/home")
			w.WriteHeader(302)
		})
		out, err := rundeck.Attempt(context.Background(), d, origin)
		if err != nil || !out.Success {
			t.Fatalf("out %+v err %v", out, err)
		}
	})
}

// A control that is locked out or rate-limited ends the attempt before the
// pair is sent.
func TestAControlThatIsRateLimitedStopsBeforeThePair(t *testing.T) {
	var seen credSeen
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if u, _, ok := r.BasicAuth(); ok {
			seen.add(u)
			if u == "user" {
				t.Error("the pair was sent after a control was rate-limited")
			}
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(401)
	})
	d, _ := noFollowDoer()
	out, err := basicEntry("/x", basicMarker("ok")).Attempt(context.Background(), d, origin)
	if err != nil || !out.Lockout || out.Success {
		t.Fatalf("out %+v err %v", out, err)
	}
}

// Every catalog entry's path is one an answer can be told from a refusal on:
// an entry whose rule a bare refusal meets is caught by the controls, and one
// that is open to all is never a success, for the Basic and the form entries.
func TestNoCatalogEntryIsProvedByAPageThatAnswersAllTheSame(t *testing.T) {
	for _, lg := range DefaultLogins() {
		for _, body := range []string{`{"name":"x","token":"t","result":1,"items":[],"username":"admin","valid":true,"authToken":"t","code":0,"neo4j_version":"1","cluster_name":"c","rabbitmq_version":"1","uri":"u"} activemq queues rundeck opennms widget-row mongo express mongo-express password_change_required`} {
			origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprint(w, body)
			})
			d, _ := noFollowDoer()
			out, err := lg.Attempt(context.Background(), d, origin)
			if err != nil {
				t.Fatalf("%s: %v", lg.ID, err)
			}
			if out.Success {
				t.Errorf("%s: a page that answers everything alike was proved: %+v", lg.ID, out)
			}
		}
	}
}
