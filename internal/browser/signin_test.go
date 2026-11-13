package browser

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A write is the sign-in's when it carries the user name or the password
// the run gave: in the URL, a header (Basic auth too) or a body however
// its media type escapes it. A script's polling POST carries neither.
func TestCredentialsCarried(t *testing.T) {
	c := &credentials{user: "member@x.test", pass: `p@ss "w&rd\`}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("member@x.test:other"))
	for _, tc := range []struct {
		name, url, ct, body string
		hdr                 map[string]any
		want                bool
	}{
		{"json password", "http://h/api/login", "application/json", `{"email":"a","password":"p@ss \"w&rd\\"}`, nil, true},
		{"json user", "http://h/api/login", "application/json", `{"email":"member@x.test"}`, nil, true},
		{"form encoded", "http://h/api/login", "application/x-www-form-urlencoded", "email=a&password=p%40ss+%22w%26rd%5C", nil, true},
		{"form user", "http://h/login", "application/x-www-form-urlencoded", "email=member%40x.test", nil, true},
		{"multipart", "http://h/login", "multipart/form-data; boundary=XX", "--XX\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\np@ss \"w&rd\\\r\n--XX--\r\n", nil, true},
		{"basic header, no body", "http://h/login", "", "", map[string]any{"Authorization": basic}, true},
		{"query", "http://h/login?u=member%40x.test", "", "", nil, true},
		{"socket polling", "http://h/socket.io/?EIO=4&transport=polling", "text/plain;charset=UTF-8", "40", nil, false},
		{"beacon", "http://h/analytics", "text/plain", `{"event":"view"}`, nil, false},
		{"cookie names the user", "http://h/poll", "text/plain", "40", map[string]any{"Cookie": "u=member@x.test", "Referer": "http://h/?u=member@x.test"}, false},
		{"no body", "http://h/poll", "", "", nil, false},
	} {
		req := &network.Request{URL: tc.url, Method: "POST", Headers: network.Headers{}}
		for k, v := range tc.hdr {
			req.Headers[k] = v
		}
		if tc.ct != "" {
			req.Headers["Content-Type"] = tc.ct
		}
		if tc.body != "" {
			req.PostDataEntries = []*network.PostDataEntry{{Bytes: []byte(tc.body)}}
		}
		if got := c.carry(req); got != tc.want {
			t.Errorf("%s: carries %v, want %v", tc.name, got, tc.want)
		}
	}
	if (&credentials{}).carry(&network.Request{URL: "http://h/x", PostDataEntries: []*network.PostDataEntry{{Bytes: []byte("x")}}}) {
		t.Error("an empty user and password are found in every body")
	}
	// A form posted as a navigation of the page is the sign-in's only after the sign-in submitted it.
	nav := &network.Request{URL: "http://h/login", Method: "POST"}
	if c.signsIn(nav, true, "MAIN", "MAIN") {
		t.Error("a document posted before the form was submitted is the sign-in's")
	}
	c.submitted.Store(true)
	if !c.signsIn(nav, true, "MAIN", "MAIN") || c.signsIn(nav, true, "FRAME", "MAIN") || c.signsIn(nav, false, "MAIN", "MAIN") {
		t.Error("the form posted as the page's navigation is the sign-in's, a frame's or a script's is not")
	}
	var none *credentials
	if none.signsIn(nav, true, "MAIN", "MAIN") {
		t.Error("a sign-in with no credentials sends a write")
	}
}

// signinSite serves a sign-in page whose scripts POST to a polling
// endpoint on load and every 100 ms, and whose form signs in the way
// submit does; what the server saw is "METHOD path".
type signinSite struct {
	*httptest.Server
	mu  sync.Mutex
	got []string
}

func (s *signinSite) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

const (
	siteUser = "member@x.test"
	sitePass = `p@ss w&rd"1`
)

// newSignInSite: submit is the script that signs in, or "" for a form
// posted as a navigation.
func newSignInSite(submit string) *signinSite {
	s := &signinSite{}
	page := `<html><body><div id=app></div><script>
const poll = () => fetch('/socket.io/?EIO=4&transport=polling&sid=1', {method: 'POST', body: '40'}).catch(() => {});
poll(); setInterval(poll, 100);
navigator.sendBeacon('/track', '{"event":"view"}');
setTimeout(() => {
  document.getElementById('app').innerHTML = '<form id=f method=post action="/login-form"><label>Email <input id=email name=email type=email></label>' +
    '<input id=pw name=password type=password><button id=go type=submit>Log in</button></form>';
  const f = document.getElementById('f');
  ` + submit + `
}, 200);
</script></body></html>`
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		ok := false
		switch r.URL.Path {
		case "/api/login":
			form, _ := url.ParseQuery(string(body))
			ok = strings.Contains(string(body), "member@x.test") && strings.Contains(string(body), `"password":"p@ss w&rd\"1"`) ||
				form.Get("email") == siteUser && form.Get("password") == sitePass ||
				r.Header.Get("Authorization") == "Basic "+base64.StdEncoding.EncodeToString([]byte(siteUser+":"+sitePass))
		case "/login-form":
			form, _ := url.ParseQuery(string(body))
			ok = form.Get("h") == "hashed" // the page hashes both fields before it posts
			if ok {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}
		case "/dashboard":
			fmt.Fprint(w, "<html><body><h1>Welcome</h1></body></html>")
			return
		case "/", "/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page)
			return
		default:
			return
		}
		if !ok {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
		fmt.Fprint(w, `{"ok":true}`)
	}))
	return s
}

// The sign-in sends the request that carries the credentials, in each way
// a page sends them (a JSON or a form-encoded fetch, Basic auth with no
// body, a form posted as a navigation), and holds what the page's scripts
// POST meanwhile: the polling and the beacon are not sent, and are listed.
func TestSignInSendsOnlyTheSignIn(t *testing.T) {
	for _, tc := range []struct {
		name, submit, login string // login: the request the server must have got
	}{
		{"json", `f.addEventListener('submit', async e => { e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email: email.value, password: pw.value})});
    if (r.ok) document.getElementById('app').innerHTML = '<h1>Welcome</h1>'; });`, "POST /api/login"},
		{"form encoded", `f.addEventListener('submit', async e => { e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', body: new URLSearchParams({email: email.value, password: pw.value})});
    if (r.ok) document.getElementById('app').innerHTML = '<h1>Welcome</h1>'; });`, "POST /api/login"},
		{"xhr", `f.addEventListener('submit', e => { e.preventDefault();
    const x = new XMLHttpRequest(); x.open('POST', '/api/login'); x.setRequestHeader('Content-Type', 'application/json');
    x.onload = () => { if (x.status == 200) document.getElementById('app').innerHTML = '<h1>Welcome</h1>'; };
    x.send(JSON.stringify({email: email.value, password: pw.value})); });`, "POST /api/login"},
		{"header only", `f.addEventListener('submit', async e => { e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', headers: {Authorization: 'Basic ' + btoa(email.value + ':' + pw.value)}});
    if (r.ok) document.getElementById('app').innerHTML = '<h1>Welcome</h1>'; });`, "POST /api/login"},
		{"form navigation, fields hashed", `f.addEventListener('submit', () => { email.value = 'x'; pw.value = 'y'; f.insertAdjacentHTML('beforeend', '<input type=hidden name=h value=hashed>'); });`, "POST /login-form"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := startChrome(t)
			srv := newSignInSite(tc.submit)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			fetch.Reset()
			egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
			s, err := b.Login(ctx, srv.URL+"/login", siteUser, sitePass)
			if err != nil {
				t.Fatalf("%v; the server got %d requests", err, len(srv.seen()))
			}
			if tc.login == "POST /api/login" && (len(s.Answers) != 1 || string(s.Answers[0]) != `{"ok":true}`) {
				t.Errorf("the sign-in's answer is not kept: %q", s.Answers)
			}
			got := srv.seen()
			if !slices.Contains(got, tc.login) {
				t.Errorf("the sign-in was not sent: %v", got)
			}
			for _, g := range []string{"POST /socket.io/", "POST /track"} {
				if slices.Contains(got, g) {
					t.Errorf("a script's write was sent: %s (the server got %d requests)", g, len(got))
				}
			}
			want := []string{"POST " + srv.URL + "/socket.io/", "POST " + srv.URL + "/track"}
			if left := b.LeftoverWrites(); !slices.Equal(left, want) {
				t.Errorf("listed as not sent: %q, want %q", left, want)
			}
		})
	}
}

// With -browser-writes the sign-in's tab sends the page's writes as every
// page does.
func TestSignInWithBrowserWritesSendsThePagesWrites(t *testing.T) {
	b := startChrome(t)
	b.Writes = true
	srv := newSignInSite(`f.addEventListener('submit', async e => { e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', body: JSON.stringify({email: email.value, password: pw.value})});
    if (r.ok) document.getElementById('app').innerHTML = '<h1>Welcome</h1>'; });`)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	if _, err := b.Login(ctx, srv.URL+"/login", siteUser, sitePass); err != nil {
		t.Fatal(err)
	}
	if got := srv.seen(); !slices.Contains(got, "POST /socket.io/") || !slices.Contains(got, "POST /api/login") {
		t.Errorf("the server got %v", got)
	}
	if left := b.LeftoverWrites(); len(left) != 0 {
		t.Errorf("listed as not sent: %q", left)
	}
}
