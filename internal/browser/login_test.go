package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A failed sign-in names the host outside the scope it needed: where the
// page went, or else a frame or a call it was refused; not a script or an
// image.
func TestOutside(t *testing.T) {
	defer fetch.Reset()
	const main = cdp.FrameID("MAIN")
	failed := ErrLoginFailed.Error()
	egress.SetScope(func(h string) bool { return h == "app.example.com" })
	for _, c := range []struct {
		rs   []refusal
		want string
	}{
		{nil, failed},
		{[]refusal{{host: "sso.example.net", frame: main, doc: true}}, "the sign-in went to sso.example.net, outside the scope: add it with -allow sso.example.net"},
		{[]refusal{{host: "www.youtube.com", frame: "VIDEO", doc: true}}, failed + "; Chrome was not let reach www.youtube.com for it (outside the scope: add it with -allow www.youtube.com, if the sign-in needs it)"},
		{[]refusal{{host: "cdn.example.net", frame: main}, {host: "auth.example.net", frame: main, sends: true}}, failed + "; Chrome was not let reach auth.example.net for it (outside the scope: add it with -allow auth.example.net, if the sign-in needs it)"},
		{[]refusal{{host: "cdn.example.net", frame: main}}, failed},
	} {
		if err := outside("https://app.example.com/login", main, c.rs, ErrLoginFailed); err.Error() != c.want {
			t.Errorf("%+v:\n got %s\nwant %s", c.rs, err, c.want)
		}
	}
	if err := outside("https://app.example.com/login", main, []refusal{{budget: true}}, ErrLoginFailed); !errors.Is(err, neterr.ErrBudget) {
		t.Errorf("budget: %v", err)
	}
	egress.SetScope(nil)
	want := "the sign-in went to sso.example.net, outside the site of app.example.com: name both with -allow example.com -allow sso.example.net"
	if err := outside("https://app.example.com/login", main, []refusal{{host: "sso.example.net", frame: main, doc: true}}, ErrLoginFailed); err.Error() != want {
		t.Errorf("no scope: %v", err)
	}
}

func TestStoredToken(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln"
	tok, from := storedToken([]string{
		"localStorage.persist:root", `{"user":"{\"jwt\":\"eyJhbGciOiJub25lIn0.eyJzdWIiOiJvbGQifQ.\"}"}`,
		"localStorage.token", jwt,
		"sessionStorage.x", "plain",
	})
	if tok != jwt || from != "localStorage.token" {
		t.Errorf("got %q from %q", tok, from)
	}
	if tok, _ := storedToken([]string{"localStorage.lang", "en"}); tok != "" {
		t.Errorf("no token expected, got %q", tok)
	}
}

// A single-page login: the form is drawn by a script, the button stays
// disabled until both fields have values, and the answer is a cookie and a
// token the page stores.
const loginPage = `<html><body><div id=app></div><script>
setTimeout(() => {
  document.getElementById('app').innerHTML =
    '<div class=overlay style="position:fixed;inset:0;z-index:9"></div>' +
    '<form><label>Email <input id=email type=email></label>' +
    '<input id=pw type=password><button id=go type=submit disabled>Log in</button></form>';
  const f = document.querySelector('form'), b = document.getElementById('go');
  f.addEventListener('input', () => { b.disabled = !(email.value && pw.value); });
  f.addEventListener('submit', async e => {
    e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', body: JSON.stringify({email: email.value, password: pw.value})});
    if (!r.ok) { document.body.insertAdjacentHTML('beforeend', '<p>wrong</p>'); return; }
    const j = await r.json();
    localStorage.setItem('token', j.token);
    sessionStorage.setItem('bid', j.bid);
    history.pushState({}, '', '/dashboard');
    fetch('/api/me', {headers: {Authorization: 'Bearer ' + j.token}});
    document.getElementById('app').innerHTML = '<h1>Welcome</h1>';
  });
}, 300);
</script></body></html>`

func TestLogin(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtZW1iZXIifQ.c2lnbmVk"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			var body struct{ Email, Password string }
			if err := decodeJSON(r, &body); err != nil || body.Email != "member@x.test" || body.Password != "s3cret" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/", HttpOnly: true})
			fmt.Fprintf(w, `{"token":%q,"bid":7}`, jwt)
		case "/api/me":
			fmt.Fprint(w, `{"email":"member@x.test"}`)
		default:
			fmt.Fprint(w, loginPage)
		}
	}))
	defer srv.Close()
	b := &Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var told []Session
	OnLogin = func(s Session) { told = append(told, s) }
	defer func() { OnLogin = nil }()
	s, err := b.Login(ctx, srv.URL+"/login", "member@x.test", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	// What the login answered and left in storage: who signed in.
	if len(told) != 1 || len(s.Answers) != 1 || string(s.Answers[0]) != fmt.Sprintf(`{"token":%q,"bid":7}`, jwt) {
		t.Errorf("told %d times, answers %q", len(told), s.Answers)
	}
	stored := map[string]string{}
	for i := 0; i+1 < len(s.Storage); i += 2 {
		stored[s.Storage[i]] = s.Storage[i+1]
	}
	if stored["sessionStorage.bid"] != "7" || stored["localStorage.token"] != jwt {
		t.Errorf("storage %v", stored)
	}
	if s.Bearer != jwt || s.From != "localStorage.token" {
		t.Errorf("token %q from %q", s.Bearer, s.From)
	}
	if len(s.Cookies) != 1 || s.Cookies[0] != "sid=abc123" {
		t.Errorf("cookies %v", s.Cookies)
	}
	// The calls the signed-in page made, for a check of the session: not the
	// sign-in page, not the form's own POST.
	if len(s.Gets) != 1 || s.Gets[0] != srv.URL+"/api/me" {
		t.Errorf("GETs after signing in: %v", s.Gets)
	}
	if s.URL != srv.URL+"/dashboard" {
		t.Errorf("ended on %s", s.URL)
	}
	if _, err := b.Login(ctx, srv.URL+"/login", "member@x.test", "wrong"); !errors.Is(err, ErrLoginFailed) {
		t.Errorf("wrong password: %v", err)
	}
}

func decodeJSON(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// dvwa copies DVWA's login.php: a session cookie, a per-session CSRF token
// in a hidden field, and a login only when the submit button's name came
// with a matching token; a refusal goes back to the form with a new token.
type dvwa struct {
	mu       sync.Mutex
	sessions map[string]string // PHPSESSID -> the token the form holds
	n        int
	posts    []url.Values
}

func (d *dvwa) session(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("PHPSESSID"); err == nil && d.sessions[c.Value] != "" || err == nil && c.Value != "" {
		return c.Value
	}
	d.n++
	id := fmt.Sprintf("sess%d", d.n)
	http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: id, Path: "/", HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "security", Value: "low", Path: "/"})
	return id
}

func (d *dvwa) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.session(w, r)
	switch r.URL.Path {
	case "/login.php":
		if r.Method == http.MethodPost {
			r.ParseForm()
			d.posts = append(d.posts, r.PostForm)
			ok := r.PostForm.Get("Login") != "" && r.PostForm.Get("user_token") == d.sessions[id] &&
				r.PostForm.Get("username") == "admin" && r.PostForm.Get("password") == "password"
			if ok {
				http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: id + "-in", Path: "/", HttpOnly: true})
				http.Redirect(w, r, "index.php", http.StatusFound)
				return
			}
			http.Redirect(w, r, "login.php", http.StatusFound)
			return
		}
		tok := fmt.Sprintf("tok%d", d.n*100+len(d.sessions))
		d.sessions[id] = tok
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>Login</title></head><body><form action="login.php" method="post">
<fieldset><label for="user">Username</label> <input type="text" class="loginInput" size="20" name="username"><br />
<label for="pass">Password</label> <input type="password" class="loginInput" AUTOCOMPLETE="off" size="20" name="password"><br />
<p class="submit"><input type="submit" value="Login" name="Login"></p></fieldset>
<input type='hidden' name='user_token' value='%s' /></form></body></html>`, tok)
	case "/index.php":
		w.Header().Set("Content-Type", "text/html")
		if c, err := r.Cookie("PHPSESSID"); err != nil || !strings.HasSuffix(c.Value, "-in") {
			http.Redirect(w, r, "login.php", http.StatusFound)
			return
		}
		fmt.Fprint(w, `<html><title>Welcome</title><body><a href="logout.php">Logout</a></body></html>`)
	}
}

// A form that wants its submit button's name and a hidden token from the
// same session (DVWA's login) signs in.
func TestLoginSendsTheSubmitButtonAndTheHiddenTokenOfTheSession(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	d := &dvwa{sessions: map[string]string{}}
	srv := httptest.NewServer(d)
	defer srv.Close()
	b := &Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := b.Login(ctx, srv.URL+"/login.php", "admin", "password")
	if err != nil {
		d.mu.Lock()
		t.Fatalf("%v; the form posts were %v", err, d.posts)
	}
	if s.URL != srv.URL+"/index.php" {
		t.Errorf("ended on %s", s.URL)
	}
}

// A page with no password input says what Chrome showed: where it ended,
// the status, title and size, and the inputs it has.
func TestLoginNoPasswordFieldSaysWhatChromeShowed(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Step one</title></head><body><form><input type=text name=username><input type=hidden name=user_token value=x></form></body></html>`)
	}))
	defer srv.Close()
	b := &Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := b.Login(ctx, srv.URL+"/login.php", "u", "p")
	if err == nil {
		t.Fatal("signed in on a page with no password field")
	}
	for _, want := range []string{"no password field on " + srv.URL + "/login.php", "Chrome shows " + srv.URL + "/login.php (status 200)", `title "Step one"`, "bytes of HTML", "inputs: text username, hidden user_token"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// A connection the guard could not open is named in the error, not left as
// Chrome's empty response or refused connection.
func TestLoginNamesTheConnectionTheGuardCouldNotOpen(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	b := &Browser{}
	defer b.Close()
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = b.Login(ctx, "http://"+addr+"/login", "u", "p")
	if err == nil || !strings.Contains(err.Error(), "Chrome's connection to "+addr+" failed: ") {
		t.Fatalf("error %v does not name the connection to %s", err, addr)
	}
}
