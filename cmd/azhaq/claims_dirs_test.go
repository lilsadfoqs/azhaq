package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// sessionSite is a site with a sign-in form whose /logout ends the session.
type sessionSite struct {
	*httptest.Server
	mu    sync.Mutex
	asked map[string]int
	live  map[string]bool
	n     int
}

func newSessionSite(t *testing.T) *sessionSite {
	t.Helper()
	s := &sessionSite{asked: map[string]int{}, live: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.asked[r.Method+" "+r.URL.Path]++
		c, _ := r.Cookie("SID")
		ok := c != nil && s.live[c.Value]
		switch {
		case r.URL.Path == "/login" && r.Method == http.MethodPost:
			s.n++
			sid := fmt.Sprintf("s%d", s.n)
			s.live[sid] = true
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: sid, Path: "/"})
			http.Redirect(w, r, "/", http.StatusFound)
		case r.URL.Path == "/login":
			fmt.Fprint(w, `<html><body><form method=post action=/login><input name=user><input type=password name=pass></form></body></html>`)
		case r.URL.Path == "/logout":
			if ok {
				s.live[c.Value] = false
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		case !ok:
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/":
			fmt.Fprint(w, "welcome, you are signed in")
		default:
			if strings.HasPrefix(r.URL.Path, "/w") {
				fmt.Fprint(w, "page "+r.URL.Path+strings.Repeat("x", len(r.URL.Path)))
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// A word that ended the session is noticed: a -login run signs in again and
// the sweeps that ran since the last good check run again, the note counting
// what they sent; a -cookie run stops with a failure and exit 3.
func TestSweepWordThatEndsTheSessionIsNoticed(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	words := []string{}
	for i := 0; i < 12; i++ {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	words = append(words[:6], append([]string{"logout"}, words[6:]...)...)
	args := func(extra ...string) []string {
		return append([]string{"run", "-url", "", "-dirs", wlist(t, words...), "-dirs-ac=false", "-json", "-no-paths", "-no-tech", "-no-favicon", "-depth", "0", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "d.db")}, extra...)
	}
	site := newSessionSite(t)
	a := args("-login", site.URL+"/login", "-login-user", "u", "-login-pass", "p")
	a[2] = site.URL + "/"
	_, rep, code := runContract(t, a...)
	notes := strings.Join(rep.Notes, "\n")
	if !regexp.MustCompile(`the session ended \(.* answered 302 to /login\); signed in again; \d+ requests? asked again \(\d+ requests sent in the same stretch by sweeps and page tasks: those run again\)`).MatchString(notes) {
		t.Errorf("-login: notes %q: want the session ended, signed in again, and the sweeps counted", rep.Notes)
	}
	site.mu.Lock()
	signedIn := site.asked["POST /login"]
	site.mu.Unlock()
	if signedIn < 2 {
		t.Errorf("-login: %d sign-ins, want a second one after the logout", signedIn)
	}
	_ = code
	// A session given by -cookie cannot be renewed: the run stops with a failure, exit 3.
	site2 := newSessionSite(t)
	site2.live["good"] = true
	b := args("-cookie", "SID=good")
	b[2] = site2.URL + "/"
	_, rep, code = runContract(t, b...)
	failed := fmt.Sprint(rep.Failed)
	if code != exitPartial || !strings.Contains(failed, "the session ended") {
		t.Errorf("-cookie: exit %d, failures %v, want exit 3 and a failure that says the session ended", code, rep.Failed)
	}
}

// The request is ffuf's: no Accept, Accept-Encoding gzip, the User-Agent of a
// current Chrome (not ffuf's); a -H of the user's wins.
func TestDirsRequestIsFfufsWithAChromeUserAgent(t *testing.T) {
	var mu sync.Mutex
	var heads []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		heads = append(heads, r.Header.Clone())
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer srv.Close()
	sweep := func(extra ...string) {
		mu.Lock()
		heads = nil
		mu.Unlock()
		if _, _, err := captureBoth(t, func() error {
			return cmdDirs(append([]string{"-u", srv.URL + "/", "-w", wlist(t, "a", "b"), "-ac=false", "-ledger", "off", "-silent"}, extra...))
		}); err != nil {
			t.Fatal(err)
		}
	}
	sweep()
	mu.Lock()
	if len(heads) != 2 {
		t.Fatalf("%d requests", len(heads))
	}
	for _, h := range heads {
		if h.Get("Accept") != "" || h.Get("Accept-Encoding") != "gzip" || !strings.Contains(h.Get("User-Agent"), "Chrome/") || strings.Contains(h.Get("User-Agent"), "Fuzz Faster U Fool") {
			t.Errorf("headers %v", h)
		}
	}
	mu.Unlock()
	sweep("-H", "User-Agent: my-agent", "-H", "Accept: text/html")
	mu.Lock()
	defer mu.Unlock()
	for _, h := range heads {
		if h.Get("User-Agent") != "my-agent" || h.Get("Accept") != "text/html" {
			t.Errorf("a -H of the user's did not win: %v", h)
		}
	}
}

// -proxy (an http, https or socks5 URL) sends every request through it, the
// calibration guesses included; calibration asks 4 guesses for each directory
// and one more for each extension; with -ac=false there are none.
func TestDirsProxyCarriesEveryRequestAndCalibrationHasFourGuesses(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer target.Close()
	stand := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer stand.Close()
	words := wlist(t, "admin", "docs", "x")
	sweep := func(proxy string, extra ...string) report {
		mu.Lock()
		paths = nil
		mu.Unlock()
		_, errOut, err := captureBoth(t, func() error {
			return cmdDirs(append([]string{"-u", target.URL + "/", "-w", words, "-proxy", proxy, "-ledger", "off", "-json"}, extra...))
		})
		if err != nil {
			t.Fatalf("%s: %v\n%s", proxy, err, errOut)
		}
		return lastReport(t, errOut)
	}
	var seen int64
	// An http proxy that delivers to the stand-in: a request that went round it would not reach it.
	hp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&seen, 1)
		resp, err := http.Get(stand.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		resp.Body.Close()
		w.WriteHeader(404)
	}))
	defer hp.Close()
	rep := sweep(hp.URL)
	mu.Lock()
	got := len(paths)
	mu.Unlock()
	if int64(got) != atomic.LoadInt64(&seen) || got != int(rep.Requests) || got != 3+4 {
		t.Errorf("proxy saw %d, the summary counts %d requests: want the 3 words and the 4 guesses of one directory, all through it", seen, rep.Requests)
	}
	rep = sweep(hp.URL, "-e", "php,bak")
	mu.Lock()
	got = len(paths)
	mu.Unlock()
	if got != int(rep.Requests) || got != 3*3+4+2 {
		t.Errorf("with two extensions: %d requests, want 9 words and 4+2 guesses", got)
	}
	rep = sweep(hp.URL, "-ac=false")
	mu.Lock()
	got = len(paths)
	mu.Unlock()
	if got != 3 || rep.Requests != 3 {
		t.Errorf("-ac=false: %d requests, want only the 3 words", got)
	}
	// https and socks5 proxies carry them too.
	addr, asked := socksProxy(t, strings.TrimPrefix(stand.URL, "http://"))
	rep = sweep("socks5://" + addr)
	mu.Lock()
	got = len(paths)
	mu.Unlock()
	if got != 3+4 || len(asked()) == 0 || int(rep.Requests) != got {
		t.Errorf("socks5: %d requests reached the stand-in, the proxy was asked %d times", got, len(asked()))
	}
}

// A sweep of a service that does not answer stops at its first words, with
// or without calibration, and lists it as unreachable.
func TestDirsDeadServiceWithoutCalibrationStopsAfterTheFirstWords(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	words := make([]string, 50)
	for i := range words {
		words[i] = fmt.Sprintf("w%d", i)
	}
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", "http://" + addr + "/", "-w", wlist(t, words...), "-ac=false", "-json", "-ledger", "off"})
	})
	rep := lastReport(t, errOut)
	if exitCode(err) != exitPartial || len(rep.Unreachable) != 1 || rep.Requests > 4 {
		t.Errorf("exit %d, unreachable %v, %d requests: want a stop after the first two words (and a retry each)", exitCode(err), rep.Unreachable, rep.Requests)
	}
}

// An answer cut off before its body ended is asked once more and never a
// hit; the summary counts the paths that got no whole answer, and the exit is 3.
func TestDirsCutOffAnswersAreCountedAndExit3(t *testing.T) {
	shell := strings.Repeat("<p>shell</p>", 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cut1" || r.URL.Path == "/cut2" {
			w.Header().Set("Content-Length", "5000")
			w.WriteHeader(200)
			w.Write([]byte(shell[:50]))
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		if r.URL.Path == "/admin" {
			w.WriteHeader(403)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	out, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wlist(t, "admin", "cut1", "cut2", "x"), "-ac=false", "-t", "1", "-json", "-ledger", "off"})
	})
	rep := lastReport(t, errOut)
	if exitCode(err) != exitPartial || !strings.Contains(strings.Join(rep.Notes, "\n"), "2 paths got no whole answer, after one retry: they were not judged") {
		t.Errorf("exit %d, notes %q", exitCode(err), rep.Notes)
	}
	if strings.Contains(out, "cut1") || strings.Contains(out, "cut2") || !strings.Contains(out, "/admin") {
		t.Errorf("a cut-off answer was listed, or the 403 was not: %s", out)
	}
}

// Without -proxy, HTTP_PROXY applies by Go's rule: a loopback target stays
// direct, a name goes through the proxy, and NO_PROXY keeps a name direct.
// Go reads the environment once, so each run is a process of its own.
func TestDirsEnvironmentProxyFollowsGosRule(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 200})
	px, seen := countingProxy(srv, false, 0)
	defer px.Close()
	port := strings.Split(srv.URL, ":")[2]
	words := wlist(t, "admin", "x")
	runIt := func(target string, env []string, extra ...string) (hits int, errOut string) {
		args := append([]string{"dirs", "-u", target, "-w", words, "-ac=false", "-ledger", "off", "-json"}, extra...)
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), append([]string{"AZHAQ_TEST_AS_MAIN=1", "AZHAQ_DATA_DIR=" + t.TempDir(), "HTTP_PROXY=" + px.URL, "http_proxy=" + px.URL, "NO_PROXY=", "no_proxy="}, env...)...)
		var out, e strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &e
		cmd.Run()
		return strings.Count(out.String(), `"url":`), e.String()
	}
	if hits, e := runIt(srv.URL+"/", nil); hits != 1 || len(seen()) != 0 {
		t.Errorf("a loopback target: %d hits, proxy saw %v: want direct\n%s", hits, seen(), e)
	}
	if _, e := runIt("http://app.test:"+port+"/", nil, "-allow", "app.test"); len(seen()) != 2 {
		t.Errorf("a name: proxy saw %v: want the 2 words through the proxy\n%s", seen(), e)
	}
	before := len(seen())
	if _, _ = runIt("http://app.test:"+port+"/", []string{"NO_PROXY=app.test", "no_proxy=app.test"}, "-allow", "app.test"); len(seen()) != before {
		t.Errorf("NO_PROXY=app.test: the proxy saw %d more: want the name direct", len(seen())-before)
	}
	// -proxy sends everything, loopback included, whatever the environment says.
	before = len(seen())
	if hits, _ := runIt(srv.URL+"/", nil, "-proxy", px.URL); hits != 1 || len(seen())-before != 2 {
		t.Errorf("-proxy: %d hits, proxy saw %d requests, want the 2 words through it", hits, len(seen())-before)
	}
}

// -rate paces every request, the calibration guesses included.
func TestDirsRatePacesTheCalibrationGuesses(t *testing.T) {
	srv := dirsServer(t, nil)
	var ws []string
	for i := 0; i < 12; i++ {
		ws = append(ws, fmt.Sprintf("w%d", i))
	}
	start := time.Now()
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wlist(t, ws...), "-rate", "20", "-t", "1", "-ledger", "off", "-json"})
	})
	took := time.Since(start)
	rep := lastReport(t, errOut)
	if err != nil || rep.Requests != 12+4 {
		t.Fatalf("%v: %d requests, want the 12 words and 4 guesses", err, rep.Requests)
	}
	// The pace lets a burst of rate/5 through: 4 requests, then 20 a second.
	if min := time.Duration(float64(rep.Requests-4) / 20 * 0.9 * float64(time.Second)); took < min {
		t.Errorf("%d requests at -rate 20 took %s, under %s: the guesses were not paced", rep.Requests, took, min)
	}
}
