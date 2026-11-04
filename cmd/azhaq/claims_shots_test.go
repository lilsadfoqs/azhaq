package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

func shotPage(title string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>%s</title></head><body><h1>hi</h1></body></html>`, title)
	})
}

func nmapFileFor(t *testing.T, ports ...[2]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>`)
	for _, p := range ports {
		fmt.Fprintf(&b, `<port protocol="tcp" portid="%s"><state state="open"/><service name="%s"/></port>`, p[0], p[1])
	}
	b.WriteString(`</ports></host></nmaprun>`)
	p := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// tlsOnly serves h over TLS on a port that drops a connection that does not
// open with a TLS handshake, as a server with nothing to say in plain HTTP does.
func tlsOnly(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.Listener = &tlsFirstListener{Listener: ts.Listener}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

type tlsFirstListener struct{ net.Listener }

func (l *tlsFirstListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pc := &peekConn{Conn: c}
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil || b[0] != 0x16 {
			c.Close()
			continue
		}
		pc.first = b
		return pc, nil
	}
}

type peekConn struct {
	net.Conn
	first []byte
}

func (c *peekConn) Read(p []byte) (int, error) {
	if len(c.first) > 0 {
		n := copy(p, c.first)
		c.first = c.first[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// A port nmap named a web service is tried over its scheme and no other; any
// other port over https, then http.
func TestShotsNmapPortsAreTriedOverTheirSchemeOrHTTPSThenHTTP(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	port := func(srv *httptest.Server) string { u, _ := url.Parse(srv.URL); return u.Port() }
	tlsOdd := tlsOnly(t, shotPage("tls odd"))                // named nessus, https only
	plainOdd := httptest.NewServer(shotPage("plain odd"))    // named nessus, http only
	tlsNamedHTTP := tlsOnly(t, shotPage("wrong"))            // named http, but it speaks https
	plainNamedHTTPS := httptest.NewServer(shotPage("wrong")) // named https, but it speaks http
	for _, s := range []*httptest.Server{tlsOdd, plainOdd, tlsNamedHTTP, plainNamedHTTPS} {
		defer s.Close()
	}
	xml := nmapFileFor(t, [2]string{port(tlsOdd), "nessus"}, [2]string{port(plainOdd), "nessus"},
		[2]string{port(tlsNamedHTTP), "http"}, [2]string{port(plainNamedHTTPS), "https"})
	js, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-nmap", xml, "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	rows := map[string]map[string]any{}
	for _, r := range shotRowsOf(t, js) {
		rows[fmt.Sprint(r["url"])] = r
	}
	if r := rows["https://127.0.0.1:"+port(tlsOdd)+"/"]; r == nil || r["file"] == nil {
		t.Errorf("a port named nessus that speaks https was not shot over https: %v", rows)
	}
	if r := rows["http://127.0.0.1:"+port(plainOdd)+"/"]; r == nil || r["file"] == nil {
		t.Errorf("a port named nessus that speaks http was not shot over http: %v", rows)
	}
	for named, hp := range map[string]string{"http://127.0.0.1:" + port(tlsNamedHTTP) + "/": "http", "https://127.0.0.1:" + port(plainNamedHTTPS) + "/": "https"} {
		if r := rows[named]; r == nil || r["failed"] != true || r["file"] != nil {
			t.Errorf("a port named %s tried over the other scheme: row %v for %s, want a failure", hp, r, named)
		}
	}
	// They are failures like any other target's: counted in the summary, the exit
	// code the shared rule's (0 while some target answered, 3 with -strict-exit).
	if rep := lastReport(t, errOut); exitCode(err) != exitOK || rep.Failures != 2 || len(rep.Failed) == 0 {
		t.Errorf("exit %d, %d failures: want the 2 ports named http and https counted, exit 0 as 2 targets answered\n%s", exitCode(err), rep.Failures, errOut)
	}
	_, errOut, err = captureBoth(t, func() error {
		return cmdShots([]string{"-nmap", xml, "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-strict-exit"})
	})
	if exitCode(err) != exitPartial {
		t.Errorf("-strict-exit: exit %d, want 3\n%s", exitCode(err), errOut)
	}
}

// A target with no picture is a failed row with its error (and a text line
// ending "failed: " and the error), or, when it is not a failure, a row with a
// note (and a line ending "no screenshot: " and the note).
func TestShotMissRowsAndLinesSayFailureOrNote(t *testing.T) {
	failed := shotMiss{target: "http://slow.test/", why: "timeout", failed: true}
	if r := shotMissRow(failed); r["url"] != "http://slow.test/" || r["failed"] != true || r["error"] != "timeout" || r["note"] != nil {
		t.Errorf("failed row %v", r)
	}
	if l := shotMissLine(failed); l != "http://slow.test/  failed: timeout" {
		t.Errorf("failed line %q", l)
	}
	note := shotMiss{target: "quiet.test", why: "no web service on 443 or 80 (connection refused)"}
	if r := shotMissRow(note); r["url"] != "quiet.test" || r["failed"] != false || r["note"] != note.why || r["error"] != nil {
		t.Errorf("note row %v", r)
	}
	if l := shotMissLine(note); l != "quiet.test  no screenshot: no web service on 443 or 80 (connection refused)" {
		t.Errorf("note line %q", l)
	}
}

// A page left alone by -shot-codes is not a failure: its row has failed:false and a note.
func TestShotsCodesLeaveAPageAloneWithANote(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/gone" {
			w.WriteHeader(404)
		}
		fmt.Fprint(w, `<html><head><title>t</title></head><body><h1>hi</h1></body></html>`)
	}))
	defer site.Close()
	js, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/gone", "-u", site.URL + "/", "-shot-codes", "200", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if err != nil {
		t.Fatalf("exit %d\n%s", exitCode(err), errOut)
	}
	rows := map[string]map[string]any{}
	for _, r := range shotRowsOf(t, js) {
		rows[fmt.Sprint(r["url"])] = r
	}
	if r := rows[site.URL+"/"]; r == nil || r["file"] == nil {
		t.Errorf("the page that answered 200 has no picture: %v", rows)
	}
	r := rows[site.URL+"/gone"]
	if r == nil || r["failed"] != false || r["file"] != nil || !strings.Contains(fmt.Sprint(r["note"]), "-shot-codes") {
		t.Errorf("the 404: row %v, want failed:false and a note naming -shot-codes", r)
	}
}

// Chrome is held to the scope, and any -allow replaces the default scope (the
// page's own host): with only the CDN's host the page itself is outside it, and
// with both nothing is blocked.
func TestShotsAllowReplacesTheDefaultScope(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var cdnHits int
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cdnHits++; fmt.Fprint(w, "x") }))
	defer cdn.Close()
	cu, _ := url.Parse(cdn.URL)
	o := "http://localhost:" + cu.Port()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>app</title><link rel=stylesheet href="%s/bootstrap.css"></head><body><h1>hi</h1></body></html>`, o)
	}))
	defer site.Close()
	run := func(allow ...string) map[string]any {
		args := []string{"-u", site.URL + "/", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"}
		for _, a := range allow {
			args = append(args, "-allow", a)
		}
		js, errOut, err := captureBoth(t, func() error { return cmdShots(args) })
		rows := shotRowsOf(t, js)
		if len(rows) != 1 {
			t.Fatalf("%v: %d rows (exit %d)\n%s\n%s", allow, len(rows), exitCode(err), js, errOut)
		}
		return rows[0]
	}
	// By default the CDN's host is outside the scope: never asked, the page partial.
	cdnHits = 0
	r := run()
	if r["partial"] != true || r["blocked"] != float64(1) || cdnHits != 0 {
		t.Errorf("no -allow: row %v, the CDN was asked %d times", r, cdnHits)
	}
	// -allow localhost replaces the default: the page's own host is now outside it.
	_, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/", "-allow", "localhost", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
	})
	if exitCode(err) != exitUsage || cdnHits != 0 {
		t.Errorf("-allow localhost alone: exit %d, the CDN was asked %d times: the page's own host should be outside the scope", exitCode(err), cdnHits)
	}
	_ = errOut
	// Both: the page is whole and the CDN is asked.
	r = run("127.0.0.1", "localhost")
	if r["partial"] == true || r["file"] == nil || cdnHits == 0 {
		t.Errorf("-allow of both hosts: row %v, the CDN was asked %d times", r, cdnHits)
	}
}

// Chrome is started once for the run, whatever AZHAQ_CHROME names; a run of
// several pages starts it a single time.
func TestShotsStartChromeOnceAndAZHAQCHROMENamesIt(t *testing.T) {
	real, err := browser.Find()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	count := filepath.Join(dir, "starts")
	wrapper := filepath.Join(dir, "chrome")
	script := "#!/bin/sh\necho start >> '" + count + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZHAQ_CHROME", wrapper)
	site := httptest.NewServer(shotPage("one"))
	defer site.Close()
	js, errOut, err := captureBoth(t, func() error {
		return cmdShots([]string{"-u", site.URL + "/a", "-u", site.URL + "/b", "-u", site.URL + "/c", "-dir", filepath.Join(dir, "s"), "-db", filepath.Join(dir, "w.db"), "-json"})
	})
	if err != nil || len(shotRowsOf(t, js)) != 3 {
		t.Fatalf("exit %d, %d rows\n%s", exitCode(err), len(shotRowsOf(t, js)), errOut)
	}
	raw, _ := os.ReadFile(count)
	if n := strings.Count(string(raw), "start"); n != 1 {
		t.Errorf("the browser named by AZHAQ_CHROME was started %d times for 3 pages, want once", n)
	}
	_ = net.IPv4len
}

// A page not fully loaded when the picture was taken has partial, unloaded,
// resources and a note, and the run exits 3; a page whole has none of them.
func TestShotsPageNotFullyLoadedIsPartialAndExits3(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow.png", "/slow.js", "/slow.woff2", "/slow.mp4":
			select {
			case <-r.Context().Done():
			case <-time.After(20 * time.Second):
			}
		case "/whole":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><h1>whole</h1></body></html>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><style>@font-face{font-family:f;src:url(/slow.woff2)}body{font-family:f}</style></head><body>text<img src="/slow.png"><script src="/slow.js"></script></body></html>`)
		}
	}))
	defer site.Close()
	run := func(path string) (map[string]any, int) {
		js, _, err := captureBoth(t, func() error {
			return cmdShots([]string{"-u", site.URL + path, "-shot-timeout", "4s", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
		})
		rows := shotRowsOf(t, js)
		if len(rows) != 1 {
			t.Fatalf("%s: %d rows", path, len(rows))
		}
		return rows[0], exitCode(err)
	}
	r, code := run("/")
	if r["partial"] != true || r["unloaded"] != float64(3) || r["resources"] != float64(3) || r["resources"] == nil || r["note"] == nil || r["file"] == nil || code != exitPartial {
		t.Errorf("a page with an image, a script and a font that never came: row %v, exit %d, want partial, unloaded 3 of 3, resources, a note and exit 3", r, code)
	}
	r, code = run("/whole")
	if r["partial"] != nil || r["unloaded"] != nil || r["note"] != nil || code != exitOK {
		t.Errorf("a whole page: row %v, exit %d", r, code)
	}
}

// A run that stopped before it came to a target leaves it without a row, and
// azhaq resume asks it.
func TestShotsStoppedRunLeavesTheRestForResume(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var paths []string
	var mu sync.Mutex
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>t</title></head><body><h1>hi</h1></body></html>`)
	}))
	defer site.Close()
	db := filepath.Join(t.TempDir(), "w.db")
	dir := filepath.Join(t.TempDir(), "s")
	args := []string{"shots", "-dir", dir, "-db", db, "-tabs", "1", "-max-requests", "6"}
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		args = append(args, "-u", site.URL+p)
	}
	out, rep, code := runContract(t, args...)
	rows := shotRowsOf(t, out)
	if code != exitLimit || rep.Stopped == "" || len(rows) >= 4 {
		t.Fatalf("exit %d, stopped %q, %d rows: want a stop by the budget with some targets left", code, rep.Stopped, len(rows))
	}
	for _, r := range rows {
		if r["failed"] == true {
			t.Errorf("a target the run did not reach has a failed row: %v", r)
		}
	}
	before := len(rows)
	out, rep, code = runContract(t, "resume", "-db", db)
	if code != exitOK && code != exitLimit {
		t.Fatalf("resume: exit %d\n%+v", code, rep)
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	if !seen["/a"] || !seen["/b"] || !seen["/c"] || !seen["/d"] {
		t.Errorf("the pages asked in all: %v: resume left a target out", paths)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*.png")); len(files) != 4 || before >= 4 {
		t.Errorf("%d pictures after the resume (%d rows before), want the 4 targets", len(files), before)
	}
}

// -shot-wait 0 takes the page at once, before the timer that draws it; a wait
// given is waited out whatever the page is.
func TestShotsWaitZeroTakesThePageAtOnce(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>late</title><p>shell</p><script>setTimeout(() => { const h = document.createElement('h1'); h.textContent = 'drawn late'; document.body.appendChild(h) }, 900)</script>`)
	}))
	defer site.Close()
	drawn := func(wait string) bool {
		js, errOut, err := captureBoth(t, func() error {
			return cmdShots([]string{"-u", site.URL + "/", "-shot-wait", wait, "-shot-html", "-dir", filepath.Join(t.TempDir(), "s"), "-db", filepath.Join(t.TempDir(), "w.db"), "-json"})
		})
		rows := shotRowsOf(t, js)
		if err != nil || len(rows) != 1 || rows[0]["html_file"] == nil {
			t.Fatalf("%s: exit %d, rows %v\n%s", wait, exitCode(err), rows, errOut)
		}
		raw, _ := os.ReadFile(fmt.Sprint(rows[0]["html_file"]))
		return strings.Contains(string(raw), "<h1>drawn late</h1>")
	}
	if drawn("0") {
		t.Error("-shot-wait 0: the page was taken after its timer")
	}
	if !drawn("1500ms") {
		t.Error("-shot-wait 1500ms: the page was taken before its timer drew")
	}
}
