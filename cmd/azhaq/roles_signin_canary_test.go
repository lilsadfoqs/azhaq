package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// A role with no check found in what its run read gets one from the pages
// the browser asked for after signing in: each is asked without the session
// (a control), and the first the session tells apart is the check. A
// candidate the anonymous role reads alike is not chosen.
func TestSignInCanariesChooseFromTheBrowsersGets(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{} // path → requests without the session
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signed := r.Header.Get("Authorization") == "Bearer tok-alice"
		if r.Header.Get("Authorization") == "" {
			mu.Lock()
			asked[r.URL.Path]++
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/Quantitys":
			fmt.Fprint(w, `{"data":[{"id":1,"quantity":4}]}`) // the same for everyone
		case "/rest/user/whoami":
			if signed {
				fmt.Fprint(w, `{"user":{"id":2,"email":"alice@x.test"}}`)
			} else {
				fmt.Fprint(w, `{"user":{}}`)
			}
		default:
			if !signed {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"data":{"id":1}}`)
		}
	}))
	defer srv.Close()
	own := map[string]bool{"127.0.0.1": true}
	alice := role{name: "alice", headers: []string{"Authorization: Bearer tok-alice"}, session: http.Header{"Authorization": {"Bearer tok-alice"}}}
	roles := []role{{name: "anon"}, alice}
	signed := map[string]browser.Session{"alice": {Gets: []string{
		srv.URL + "/api/Quantitys", srv.URL + "/rest/basket/1", srv.URL + "/rest/user/whoami", srv.URL + "/main.js", "http://elsewhere.test/rest/user/whoami"}}}
	picked := map[string]*canary{}
	sent, notes, tried, err := signInCanaries(roles, picked, signed, srv.URL+"/login", map[string]map[string]answer{}, own, 0, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := picked["alice"]
	if c == nil || c.url != srv.URL+"/rest/user/whoami" || c.want.Status != 200 {
		t.Fatalf("canary %+v", c)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "role alice") || !strings.Contains(notes[0], "/rest/user/whoami") || !strings.Contains(notes[0], "200:") {
		t.Errorf("notes %q", notes)
	}
	// A /me comes first: one read with the session, one control.
	if sent != 2 || asked["/rest/user/whoami"] != 1 || asked["/rest/basket/1"]+asked["/api/Quantitys"] != 0 || len(tried) != 0 {
		t.Errorf("sent %d, controls %v, tried %v", sent, asked, tried)
	}
	// The check tells a live session from a dead one: the role losing its
	// session is seen on it, as on any other check.
	ctx := context.Background()
	if ok, _ := c.alive(ctx, alice.session, own, nil); !ok {
		t.Errorf("the live session did not pass its own check")
	}
	if ok, a := c.alive(ctx, http.Header{}, own, nil); ok {
		t.Errorf("a session that is gone passed the check: %+v", a)
	}

	// Only pages the anonymous role reads alike: none is chosen, and each was
	// asked once without the session.
	clear(asked)
	picked = map[string]*canary{}
	signed = map[string]browser.Session{"alice": {Gets: []string{srv.URL + "/api/Quantitys"}}}
	_, notes, tried, err = signInCanaries(roles, picked, signed, "", map[string]map[string]answer{}, own, 0, 100, nil)
	if err != nil || picked["alice"] != nil || len(notes) != 0 || tried["alice"] != 1 || asked["/api/Quantitys"] != 1 {
		t.Errorf("picked %v notes %q tried %v asked %v err %v", picked, notes, tried, asked, err)
	}

	// A check the role already has, or was given, is kept.
	given := &canary{url: srv.URL + "/mine"}
	picked = map[string]*canary{"alice": given}
	sent, _, _, _ = signInCanaries(roles, picked, map[string]browser.Session{"alice": {Gets: []string{srv.URL + "/rest/user/whoami"}}}, "", nil, own, 0, 100, nil)
	if picked["alice"] != given || sent != 0 {
		t.Errorf("a given check was replaced or asked: %+v, %d", picked["alice"], sent)
	}

	// The budget ends it, as a replay stage's cap does.
	_, _, _, err = signInCanaries(roles, map[string]*canary{}, signed, "", nil, own, 0, 1, nil)
	if !errors.Is(err, errReplayMax) {
		t.Errorf("a spent budget: %v", err)
	}
}

const juicePage = `<html><title>Shop</title><body><a href="/login">Sign in</a><div id=app></div></body></html>`

const juiceLoginPage = `<html><title>Sign in</title><body><div id=app>Loading…</div><script>
setTimeout(() => {
  document.getElementById('app').innerHTML = '<form><input id=email type=email placeholder=Email>' +
    '<input id=pw type=password><button type=submit disabled>Log in</button></form>';
  const f = document.querySelector('form'), b = f.querySelector('button');
  f.addEventListener('input', () => { b.disabled = !(email.value && pw.value); });
  f.addEventListener('submit', async e => {
    e.preventDefault();
    const r = await fetch('/rest/user/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: email.value, password: pw.value})});
    if (!r.ok) return;
    const token = (await r.json()).authentication.token;
    localStorage.setItem('token', token);
    location.href = '/home';
  });
}, 100);
</script></body></html>`

// The page after sign-in asks "who am I" with the session the sign-in left,
// a call the role maps never read: that GET is the role's session check,
// found from the sign-in, and the summary says which and what the control
// answered. The "nothing was found" note is not there.
func TestRolesSignInCanaryFoundFromTheSignIn(t *testing.T) {
	t.Run("a check is found", func(t *testing.T) { juiceSignIn(t, false) })
	t.Run("none tells the session apart", func(t *testing.T) { juiceSignIn(t, true) })
}

// juiceSignIn runs roles with two accounts signed in with Chrome on a shop
// whose home page asks "who am I"; public says the shop answers it alike
// with and without a session.
func juiceSignIn(t *testing.T, public bool) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	const password = "Bench-Passw0rd!"
	users := map[string]string{"alice@shop.test": "alice", "bob@shop.test": "bob"}
	var mu sync.Mutex
	sessions := map[string]string{}
	var whoamiAnon atomic.Int64
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := ""
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if c, err := r.Cookie("token"); err == nil && !ok {
			tok, ok = c.Value, true
		}
		if ok {
			mu.Lock()
			role = sessions[tok]
			mu.Unlock()
		}
		switch r.URL.Path {
		case "/", "/home":
			if r.URL.Path == "/home" {
				fmt.Fprint(w, `<html><title>Home</title><body><div id=app></div><script>
const t = localStorage.getItem('token');
fetch('/rest/user/' + ['who','ami'].join(''), {headers: {Authorization: 'Bearer ' + t}});
</script></body></html>`)
				return
			}
			fmt.Fprint(w, juicePage)
		case "/login":
			fmt.Fprint(w, juiceLoginPage)
		case "/rest/user/login":
			var body struct{ Email, Password string }
			if r.Method != http.MethodPost {
				http.Error(w, "post only", http.StatusMethodNotAllowed)
				return
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || users[body.Email] == "" || body.Password != password {
				http.Error(w, `{"error":"bad credentials"}`, http.StatusUnauthorized)
				return
			}
			var b [12]byte
			_, _ = rand.Read(b[:])
			token := "eyJhbGciOiJIUzI1NiJ9.eyJ0IjoxfQ." + hex.EncodeToString(b[:])
			mu.Lock()
			sessions[token] = users[body.Email]
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "token", Value: token, Path: "/"})
			fmt.Fprintf(w, `{"authentication":{"token":%q}}`, token)
		case "/rest/user/whoami":
			w.Header().Set("Content-Type", "application/json")
			if public {
				fmt.Fprint(w, `{"user":{"role":"shopper"}}`)
				return
			}
			if role == "" {
				whoamiAnon.Add(1)
				fmt.Fprint(w, `{"user":{}}`)
				return
			}
			fmt.Fprintf(w, `{"user":{"role":%q}}`, role)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	args := []string{"-json", "-dir", t.TempDir(), "-login", site.URL + "/login", "-role", "anon",
		"-role-login", "alice=alice@shop.test:" + password, "-role-login", "bob=bob@shop.test:" + password,
		"--", "-url", site.URL + "/"}
	_, errOut, err := captureBoth(t, func() error { return cmdRoles(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if public {
		for _, name := range []string{"alice", "bob"} {
			want := "role " + name + ": nothing only its session reads was found to check it by during the replay ("
			if !strings.Contains(errOut, want) || !strings.Contains(errOut, "asked without the session, and none told it apart); -canary URL gives one") {
				t.Errorf("the summary lacks %q:\n%s", want, errOut)
			}
		}
		if strings.Contains(errOut, "its session is checked on") {
			t.Errorf("a check was chosen though no page told the session apart:\n%s", errOut)
		}
		return
	}
	if strings.Contains(errOut, "nothing only its session reads") {
		t.Errorf("a check was there to find:\n%s", errOut)
	}
	for _, name := range []string{"alice", "bob"} {
		want := "role " + name + ": its session is checked on /rest/user/whoami, a page the browser asked for after signing in; asked without the session it answered 200:"
		if !strings.Contains(errOut, want) {
			t.Errorf("the summary lacks %q:\n%s", want, errOut)
		}
	}
	if whoamiAnon.Load() < 2 {
		t.Errorf("the control (no session) was asked %d times, one for each role", whoamiAnon.Load())
	}
}
