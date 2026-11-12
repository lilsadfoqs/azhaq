package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func testDoer() HTTPDoer {
	return HTTPDoer{Client: &http.Client{}, Spend: func(context.Context) error { return nil }}
}

// countingHandler counts the requests it gets and routes each to one of
// the handlers named, by method: a fixture a test shapes without a real
// product.
type countingHandler struct {
	mu    sync.Mutex
	n     int
	serve func(n int, w http.ResponseWriter, r *http.Request)
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.n++
	n := h.n
	h.mu.Unlock()
	h.serve(n, w, r)
}

func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

func newFixture(t *testing.T, serve func(n int, w http.ResponseWriter, r *http.Request)) (origin string, h *countingHandler) {
	t.Helper()
	h = &countingHandler{serve: serve}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, h
}

func basicEntry(path string, success func(status int, body []byte) bool) DefaultLogin {
	return DefaultLogin{ID: "fixture-basic", Product: "FixtureProduct", Source: "https://example.invalid/docs", User: "user", Pass: "SuperSecretDefault1", Mode: ModeBasic, Path: path, Success: success}
}

// A fixture that takes the pair: 200 and a marker in the body.
func TestLoginAttemptAcceptedIsSuccess(t *testing.T) {
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "user" && p == "SuperSecretDefault1" {
			w.WriteHeader(200)
			w.Write([]byte("welcome, signed in"))
			return
		}
		w.WriteHeader(401)
		w.Write([]byte("unauthorized"))
	})
	lg := basicEntry("/admin", func(status int, body []byte) bool {
		return status == 200 && strings.Contains(string(body), "signed in")
	})
	out, err := lg.Attempt(context.Background(), testDoer(), origin)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Success || out.Lockout || out.CaptchaSkip {
		t.Fatalf("want success, got %+v", out)
	}
	if h.count() != 1 {
		t.Fatalf("want 1 request, got %d", h.count())
	}
}

// A fixture that refuses the pair: never a success.
func TestLoginAttemptRefusedIsNotSuccess(t *testing.T) {
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("unauthorized"))
	})
	lg := basicEntry("/admin", func(status int, body []byte) bool { return status == 200 })
	out, err := lg.Attempt(context.Background(), testDoer(), origin)
	if err != nil {
		t.Fatal(err)
	}
	if out.Success || out.Lockout || out.CaptchaSkip {
		t.Fatalf("want a plain refusal, got %+v", out)
	}
}

// Three pairs: the first fails, the second succeeds. The loop stops
// there and the third, which would also succeed, is never sent.
func TestAttemptLoginsStopsAtFirstSuccess(t *testing.T) {
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		if u == "second" {
			w.WriteHeader(200)
			w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(401)
	})
	pairs := []DefaultLogin{
		{ID: "p1", Product: "x", User: "first", Pass: "p1", Mode: ModeBasic, Path: "/", Success: basicMarker("ok")},
		{ID: "p2", Product: "x", User: "second", Pass: "p2", Mode: ModeBasic, Path: "/", Success: basicMarker("ok")},
		{ID: "p3", Product: "x", User: "third", Pass: "p3", Mode: ModeBasic, Path: "/", Success: basicMarker("ok")},
	}
	lg, out, tried, err := AttemptLogins(context.Background(), testDoer(), origin, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Success || lg.ID != "p2" {
		t.Fatalf("want p2 to succeed, got lg=%+v out=%+v", lg, out)
	}
	if tried != 2 {
		t.Fatalf("want 2 pairs tried, got %d", tried)
	}
	if h.count() != 2 {
		t.Fatalf("want exactly 2 requests sent (never a third), got %d", h.count())
	}
}

// 429 on the first attempt stops the loop: a second pair, which would
// succeed, is never sent.
func TestAttemptLoginsStopsOn429NoSecondAttempt(t *testing.T) {
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			w.WriteHeader(429)
			w.Write([]byte("too many requests"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("ok")) // never reached: proves the second pair was not sent
	})
	pairs := []DefaultLogin{
		{ID: "p1", Product: "x", User: "first", Pass: "p1", Mode: ModeBasic, Path: "/", Success: basicMarker("ok")},
		{ID: "p2", Product: "x", User: "second", Pass: "p2", Mode: ModeBasic, Path: "/", Success: basicMarker("ok")},
	}
	_, out, tried, err := AttemptLogins(context.Background(), testDoer(), origin, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Lockout || out.Success {
		t.Fatalf("want a lockout from the 429, got %+v", out)
	}
	if tried != 1 {
		t.Fatalf("want exactly 1 pair tried, got %d", tried)
	}
	if h.count() != 1 {
		t.Fatalf("want exactly 1 request sent, got %d", h.count())
	}
}

// A lockout sign in the body, not a 429, also stops the loop.
func TestAttemptLoginsStopsOnLockoutMarker(t *testing.T) {
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Account temporarily disabled after too many failed attempts"))
	})
	pairs := []DefaultLogin{
		{ID: "p1", Product: "x", User: "first", Pass: "p1", Mode: ModeBasic, Path: "/", Success: basicMarker("never-matches")},
		{ID: "p2", Product: "x", User: "second", Pass: "p2", Mode: ModeBasic, Path: "/", Success: basicMarker("never-matches")},
	}
	_, out, tried, err := AttemptLogins(context.Background(), testDoer(), origin, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Lockout {
		t.Fatalf("want a lockout from the body's own sign, got %+v", out)
	}
	if tried != 1 || h.count() != 1 {
		t.Fatalf("want exactly 1 pair tried and 1 request sent, got tried=%d requests=%d", tried, h.count())
	}
}

// A sign-in page with a captcha field is never sent a credential: the
// GET of the page is the only request, and the loop stops there.
func TestAttemptLoginsCaptchaNeverSendsACredential(t *testing.T) {
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(200)
			w.Write([]byte(`<form><input name="g-recaptcha-response"></form>`))
			return
		}
		t.Fatalf("a POST was sent to a captcha-protected sign-in page: %s %s", r.Method, r.URL)
	})
	pairs := []DefaultLogin{
		{ID: "p1", Product: "x", User: "u", Pass: "p1", Mode: ModeForm, Path: "/login", UserField: "user", PassField: "pass", CaptchaCheck: true, Success: basicMarker("never")},
	}
	lg, out, tried, err := AttemptLogins(context.Background(), testDoer(), origin, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if !out.CaptchaSkip || out.Tried {
		t.Fatalf("want a captcha skip with no credential sent, got %+v", out)
	}
	if lg.ID != "p1" || tried != 1 {
		t.Fatalf("want the one entry counted as tried (evaluated, not credentialed), got lg=%+v tried=%d", lg, tried)
	}
	if h.count() != 1 {
		t.Fatalf("want exactly 1 request (the page GET, never a POST), got %d", h.count())
	}
}

// The password is never in what Attempt returns, even when a careless
// fixture echoes it back in the body.
func TestLoginAttemptNeverReturnsThePassword(t *testing.T) {
	const pass = "Sup3rSecretEcho"
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		_, p, _ := r.BasicAuth()
		w.WriteHeader(401)
		fmt.Fprintf(w, "denied for password %s", p) // a careless server: still must not leak through us
	})
	lg := DefaultLogin{ID: "p1", Product: "x", User: "u", Pass: pass, Mode: ModeBasic, Path: "/", Success: basicMarker("never")}
	out, err := lg.Attempt(context.Background(), testDoer(), origin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Excerpt, pass) || strings.Contains(out.Request, pass) {
		t.Fatalf("the password leaked into the outcome: %+v", out)
	}
}

// An entry with no empty-password case: MikroTik-style, Pass == "" is
// also never a problem for redact (nothing to replace).
func TestRedactEmptyPasswordIsANoop(t *testing.T) {
	if got := redact("hello world", ""); got != "hello world" {
		t.Fatalf("redact with an empty password changed the text: %q", got)
	}
}

// UnauthRead: a finding only when the unauthenticated answer shows the
// protected content, whatever the wrong-credential answer shows.
func TestUnauthReadFindingOnlyWhenUnauthenticatedShowsContent(t *testing.T) {
	shown := func(status int, body []byte) bool {
		return status == 200 && strings.Contains(string(body), "SECRET-ADMIN-DATA")
	}
	t.Run("shows content unauthenticated: a finding", func(t *testing.T) {
		origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("cluster status: SECRET-ADMIN-DATA"))
		})
		u := UnauthRead{ID: "u1", Product: "x", Path: "/status", Shown: shown}
		finding, req, ev, err := u.Check(context.Background(), testDoer(), origin)
		if err != nil {
			t.Fatal(err)
		}
		if !finding {
			t.Fatalf("want a finding, request=%q evidence=%q", req, ev)
		}
		if h.count() != 2 {
			t.Fatalf("want both the unauthenticated and the wrong-credential read sent, got %d", h.count())
		}
	})
	t.Run("shows a login unauthenticated: no finding", func(t *testing.T) {
		origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			w.Write([]byte("please sign in"))
		})
		u := UnauthRead{ID: "u1", Product: "x", Path: "/status", Shown: shown}
		finding, _, _, err := u.Check(context.Background(), testDoer(), origin)
		if err != nil {
			t.Fatal(err)
		}
		if finding {
			t.Fatal("want no finding: the unauthenticated answer showed no protected content")
		}
	})
	t.Run("both answers show content: still a finding (the comparison is evidence, not a gate)", func(t *testing.T) {
		origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("cluster status: SECRET-ADMIN-DATA")) // no auth check at all: the classic bypass
		})
		u := UnauthRead{ID: "u1", Product: "x", Path: "/status", Shown: shown}
		finding, _, _, err := u.Check(context.Background(), testDoer(), origin)
		if err != nil {
			t.Fatal(err)
		}
		if !finding {
			t.Fatal("want a finding: the product has no authentication at all, so both reads show the content")
		}
	})
}

// The wrong credential is fixed and is not a guess at any real pair.
func TestUnauthReadWrongCredentialIsNeverARealPair(t *testing.T) {
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n == 2 {
			u, p, ok := r.BasicAuth()
			if !ok || u != wrongCredUser || p != wrongCredPass {
				t.Fatalf("the second read's credential was not the fixed wrong one: %s/%s", u, p)
			}
		}
		w.WriteHeader(401)
	})
	u := UnauthRead{ID: "u1", Product: "x", Path: "/", Shown: func(int, []byte) bool { return false }}
	if _, _, _, err := u.Check(context.Background(), testDoer(), origin); err != nil {
		t.Fatal(err)
	}
}

// Every catalog entry is sourced (a vendor doc or advisory URL), has a
// non-empty user, and its mode's own fields are set: nothing in the
// catalog is a placeholder.
func TestCatalogEntriesAreSourcedAndComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, lg := range DefaultLogins() {
		if lg.ID == "" || seen[lg.ID] {
			t.Fatalf("default-login id %q is empty or repeated", lg.ID)
		}
		seen[lg.ID] = true
		if lg.Product == "" {
			t.Fatalf("%s: no product", lg.ID)
		}
		if !strings.HasPrefix(lg.Source, "http://") && !strings.HasPrefix(lg.Source, "https://") {
			t.Fatalf("%s: source %q is not a URL", lg.ID, lg.Source)
		}
		if lg.User == "" {
			t.Fatalf("%s: no user", lg.ID)
		}
		if lg.Success == nil {
			t.Fatalf("%s: no success judgement", lg.ID)
		}
		switch lg.Mode {
		case ModeBasic:
			if lg.Path == "" {
				t.Fatalf("%s: no path", lg.ID)
			}
		case ModeForm:
			if lg.Path == "" || lg.UserField == "" || lg.PassField == "" {
				t.Fatalf("%s: ModeForm missing path or field names", lg.ID)
			}
		case ModeJSON:
			if lg.Path == "" || lg.Body == nil {
				t.Fatalf("%s: ModeJSON missing path or body", lg.ID)
			}
		}
	}
	seenR := map[string]bool{}
	for _, u := range UnauthReads() {
		if u.ID == "" || seenR[u.ID] {
			t.Fatalf("unauthenticated-read id %q is empty or repeated", u.ID)
		}
		seenR[u.ID] = true
		if u.Product == "" || u.Path == "" {
			t.Fatalf("%s: missing product or path", u.ID)
		}
		if !strings.HasPrefix(u.Source, "http://") && !strings.HasPrefix(u.Source, "https://") {
			t.Fatalf("%s: source %q is not a URL", u.ID, u.Source)
		}
		if u.Shown == nil {
			t.Fatalf("%s: no Shown judgement", u.ID)
		}
	}
	if n := len(DefaultLogins()) + len(UnauthReads()); n < 20 || n > 40 {
		t.Fatalf("want 20 to 40 catalog entries in all, got %d", n)
	}
}

// LoginsForProduct and ReadsForProduct match case- and
// separator-insensitively, and a product with no entry gets none.
func TestLoginsForProductMatchesByNormalizedName(t *testing.T) {
	if lgs := LoginsForProduct("  SonarQube  "); len(lgs) != 1 || lgs[0].ID != "sonarqube-admin-admin" {
		t.Fatalf("want the one SonarQube entry, got %+v", lgs)
	}
	if lgs := LoginsForProduct("mongo express"); len(lgs) != 1 {
		t.Fatalf("want mongo-express to match with a space instead of a hyphen, got %+v", lgs)
	}
	if lgs := LoginsForProduct("NoSuchProductAtAll"); len(lgs) != 0 {
		t.Fatalf("want no entries for an unknown product, got %+v", lgs)
	}
	if rs := ReadsForProduct("hadoop yarn"); len(rs) != 1 {
		t.Fatalf("want the one Hadoop YARN entry, got %+v", rs)
	}
}

// No mode ever puts the pair in the request's query string: the ledger
// keeps the URL of every request (never a header, and a body only as
// its hash), so a mode that did would leak the password into it. Every
// catalog entry's request carries no query string at all.
func TestNoModeEverSendsAQueryString(t *testing.T) {
	for _, lg := range DefaultLogins() {
		origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "" {
				t.Errorf("%s: the request carries a query string, which the ledger keeps: %q", lg.ID, r.URL.RawQuery)
			}
			w.WriteHeader(200)
		})
		if _, err := lg.Attempt(context.Background(), testDoer(), origin); err != nil {
			t.Fatalf("%s: %v", lg.ID, err)
		}
	}
}

// ModeForm sends url-encoded fields; ModeJSON sends a JSON body: both
// carry the pair and nothing else distinguishes them to the fixture.
func TestModeFormAndModeJSONSendTheFieldsNamed(t *testing.T) {
	origin, _ := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		switch {
		case strings.Contains(ct, "json"):
			buf := make([]byte, 256)
			nr, _ := r.Body.Read(buf)
			if !strings.Contains(string(buf[:nr]), `"user"`) {
				t.Fatalf("want the JSON body to carry the user, got %q", buf[:nr])
			}
		case strings.Contains(ct, "form"):
			r.ParseForm()
			if r.Form.Get("j_username") != "user" {
				t.Fatalf("want the form field j_username=user, got %q", r.Form)
			}
		default:
			t.Fatalf("unexpected content type %q", ct)
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	form := DefaultLogin{ID: "f1", Product: "x", User: "user", Pass: "pw", Mode: ModeForm, Path: "/login", UserField: "j_username", PassField: "j_password", Success: basicMarker("ok")}
	if out, err := form.Attempt(context.Background(), testDoer(), origin); err != nil || !out.Success {
		t.Fatalf("form: out=%+v err=%v", out, err)
	}
	jsonLogin := DefaultLogin{ID: "j1", Product: "x", User: "user", Pass: "pw", Mode: ModeJSON, Path: "/login",
		Body:    func(user, pass string) []byte { return []byte(fmt.Sprintf(`{"user":%q,"pass":%q}`, user, pass)) },
		Success: basicMarker("ok")}
	if out, err := jsonLogin.Attempt(context.Background(), testDoer(), origin); err != nil || !out.Success {
		t.Fatalf("json: out=%+v err=%v", out, err)
	}
}

// Spend's own refusal (the budget, the kill file, the scope) is
// returned as the error, and no request reaches the fixture.
func TestAttemptHonorsSpendRefusal(t *testing.T) {
	origin, h := newFixture(t, func(n int, w http.ResponseWriter, r *http.Request) {
		t.Fatal("a request was sent although Spend refused it")
	})
	d := HTTPDoer{Client: &http.Client{}, Spend: func(context.Context) error { return fmt.Errorf("budget spent") }}
	lg := basicEntry("/", basicMarker("ok"))
	_, err := lg.Attempt(context.Background(), d, origin)
	if err == nil {
		t.Fatal("want the Spend error")
	}
	if h.count() != 0 {
		t.Fatalf("want no request sent, got %d", h.count())
	}
}
