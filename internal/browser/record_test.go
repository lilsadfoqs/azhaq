package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A page that calls alert() on load is shot in moments, not when its
// time is up; what Chrome saw of it (headers, console, requests) is
// kept, and the options shape the picture.
func TestDialogRecordAndOptions(t *testing.T) {
	b := startChrome(t)
	b.Width, b.Height = 700, 500
	b.Format, b.Quality = "jpeg", 40
	b.Wait = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("X-Probe", "yes")
			fmt.Fprint(w, `<html><head><title>dlg</title></head><body><script>console.log('hello'); alert('x'); document.write('<img src="/a.png">')</script></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	start := time.Now()
	p, err := b.Load(ctx, srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("a page with a dialog took %v", d)
	}
	if p.Format != "jpeg" || len(p.Image) < 3 || p.Image[0] != 0xff || p.Image[1] != 0xd8 {
		t.Errorf("not a jpeg: format %q, %d bytes", p.Format, len(p.Image))
	}
	r := p.Record
	if r.Status != 200 || r.Protocol == "" {
		t.Errorf("answer: %d %q", r.Status, r.Protocol)
	}
	if !slices.ContainsFunc(r.Headers, func(h Header) bool { return h.Key == "X-Probe" && h.Value == "yes" }) {
		t.Errorf("headers %v", r.Headers)
	}
	if !slices.ContainsFunc(r.Console, func(c ConsoleLn) bool { return c.Type == "log" && c.Value == "hello" }) {
		t.Errorf("console %v", r.Console)
	}
	if !slices.ContainsFunc(r.Network, func(n NetEntry) bool { return n.URL == srv.URL+"/a.png" && n.Status == 404 }) {
		t.Errorf("network %v", r.Network)
	}
}

// A page taller than the screen is as tall as it is with FullPage.
func TestFullPage(t *testing.T) {
	b := startChrome(t)
	b.Width, b.Height = 600, 400
	b.FullPage = true
	b.Wait = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body style="margin:0"><div style="height:2000px;background:#a33"></div></body></html>`)
	}))
	defer srv.Close()
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	p, err := b.Load(context.Background(), srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	h := int(p.Image[22])<<24 | int(p.Image[23])<<16 | int(p.Image[24])<<8 | int(p.Image[25]) // PNG IHDR height
	if h < 2000 {
		t.Errorf("full page is %d pixels tall, want 2000", h)
	}
}

// -shot-size's picture is exactly the pixels asked for: headless Chrome's
// own window chrome must not shrink it (-window-size at launch is not the
// viewport). Width and Height are set before Start, as -shot-size is.
func TestShotSizeIsExact(t *testing.T) {
	if _, err := Find(); err != nil {
		t.Skip(err)
	}
	b := &Browser{Width: 800, Height: 600, Wait: -1}
	t.Cleanup(fetch.Reset)
	if err := b.Start(); errors.Is(err, ErrNoSandbox) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body style="margin:0">hi</body></html>`)
	}))
	defer srv.Close()
	fetch.Reset()
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	p, err := b.Load(context.Background(), srv.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	w := int(p.Image[16])<<24 | int(p.Image[17])<<16 | int(p.Image[18])<<8 | int(p.Image[19]) // PNG IHDR width
	h := int(p.Image[20])<<24 | int(p.Image[21])<<16 | int(p.Image[22])<<8 | int(p.Image[23]) // PNG IHDR height
	if w != 800 || h != 600 {
		t.Errorf("picture is %dx%d, want 800x600", w, h)
	}
}

// A page whose scripts come back as its HTML shell, with an error, or not
// at all has them listed with why, and a page that threw says what.
func TestScriptFaultsAndThrew(t *testing.T) {
	r := Record{
		Network: []NetEntry{
			{rt: network.ResourceTypeScript, URL: "/ok.js", Status: 200, MIME: "text/javascript"},
			{rt: network.ResourceTypeScript, URL: "/shell.js", Status: 200, MIME: "text/html"},
			{rt: network.ResourceTypeScript, URL: "/gone.js", Status: 404, MIME: "text/plain"},
			{rt: network.ResourceTypeScript, URL: "/cut.js", Error: "net::ERR_FAILED"},
			{rt: network.ResourceTypeScript, URL: "https://cdn.example/x.js", Error: "net::ERR_BLOCKED_BY_CLIENT", blocked: true},
			{rt: network.ResourceTypeDocument, URL: "/", Status: 200, MIME: "text/html"},
		},
		Console: []ConsoleLn{{Type: "log", Value: "hi"}, {Type: "exception", Value: "TypeError: x is not a function\n    at main.js:1"}},
	}
	var got []string
	for _, f := range r.ScriptFaults() {
		got = append(got, f.URL)
	}
	if want := []string{"/shell.js", "/gone.js", "/cut.js"}; !slices.Equal(got, want) {
		t.Errorf("faults %v, want %v", got, want)
	}
	if got := r.Threw(); got != "TypeError: x is not a function" {
		t.Errorf("threw %q", got)
	}
}

// A page Chrome loads that is redirected to the sign-in page (a relative
// Location, as many PHP apps send) tells the session guard, so the run
// checks its session before it sends anything else.
func TestChromeRedirectToSignInSetsTheSessionCheck(t *testing.T) {
	b := startChrome(t)
	b.Wait = -1
	var checks atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/me":
			checks.Add(1)
			fmt.Fprint(w, "me")
		case "/login.php":
			fmt.Fprint(w, `<html><body>sign in</body></html>`)
		default:
			w.Header().Set("Location", "login.php")
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer srv.Close()
	fetch.Reset()
	defer fetch.Reset()
	fetch.Extra = http.Header{"Cookie": {"sid=abc"}}
	egress.SetScope(func(h string) bool { return h == "127.0.0.1" })
	fetch.WatchSession(fetch.Session{Check: srv.URL + "/me", Want: fetch.Print{Status: 200}, Every: 1000, SignIn: srv.URL + "/login.php"})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := fetch.CheckDue(ctx); err != nil || checks.Load() != 0 {
		t.Fatalf("before any page: %v, %d checks", err, checks.Load())
	}
	if _, err := b.Load(ctx, srv.URL+"/", false); err != nil {
		t.Fatal(err)
	}
	if err := fetch.CheckDue(ctx); err != nil || checks.Load() != 1 {
		t.Errorf("after a page redirected to the sign-in page: %v, %d checks, want 1", err, checks.Load())
	}
}
