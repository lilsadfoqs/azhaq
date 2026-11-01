package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// bigScriptApp is a single-page app whose bundle is large, slow to start
// and sent in chunks, as Juice Shop's main.js is: the bundle names a route
// table and API calls, and draws a menu with a button once it has run.
func bigScriptApp() *httptest.Server {
	var js strings.Builder
	js.WriteString("var routes=[{path:'about',component:1},{path:'basket',component:1}];fetch('/api/fromscript');")
	js.WriteString("document.getElementById('app').innerHTML='<nav><button id=b>Basket</button> <a href=\"#/about\">About</a></nav>';")
	js.WriteString("document.getElementById('b').onclick=function(){fetch('/api/'+['cli','cked'].join(''))};fetch('/api/'+['dra','wn'].join(''));\n")
	js.WriteString(strings.Repeat("function pad(a,b){return a+b*Math.random()}\n", 24000)) // about 1 MB
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><title>shop</title><body><div id="app"></div><script src="/main.js"></script></body></html>`)
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			time.Sleep(time.Second) // first byte
			body := js.String()
			var out io.Writer = w
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(w)
				defer zw.Close()
				out = zw
			}
			for len(body) > 0 {
				n := min(len(body), 64<<10)
				_, _ = fmt.Fprint(out, body[:n])
				if zw, ok := out.(*gzip.Writer); ok {
					_ = zw.Flush()
				}
				w.(http.Flusher).Flush()
				body = body[n:]
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	}))
}

// startCountProxy runs bench/truth/ledger/countproxy.py in front of site and
// returns its address and the number of requests it logged.
func startCountProxy(t *testing.T, site *httptest.Server) (addr string, logged func() int) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	script, err := filepath.Abs("../../bench/truth/ledger/countproxy.py")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	logPath := filepath.Join(t.TempDir(), "proxy.jsonl")
	cmd := exec.Command(py, "-I", script, strconv.Itoa(port), strings.TrimPrefix(site.URL, "http://127.0.0.1:"), logPath)
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	addr = fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return addr, func() int {
		raw, _ := os.ReadFile(logPath)
		return strings.Count(string(raw), "\n")
	}
}

// Behind the counting reverse proxy a big, slow bundle gives the crawl what
// it gives without the proxy: the bundle's calls, what the page's own
// script asks, what a click asks, and the -interact note.
func TestInteractBehindCountproxyWithABigSlowBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("starts Chrome and a proxy; takes 15 s")
	}
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := bigScriptApp()
	defer srv.Close()
	proxy, logged := startCountProxy(t, srv)
	t.Chdir(t.TempDir())
	crawl := func(base string, extra ...string) (map[string]bool, string, int) {
		args := append([]string{"crawl", "-u", base + "/", "-d", "1", "-browser", "-interact", "-interact-clicks", "4", "-allow", "127.0.0.1",
			"-max-requests", "200", "-json", "-db", fmt.Sprintf("c%d.db", len(extra))}, extra...)
		out, errOut, code := cli(t, args...)
		got := map[string]bool{}
		for _, r := range jsonRows(t, out) {
			got[strings.TrimPrefix(r["url"].(string), base)] = true
		}
		return got, errOut, code
	}
	direct, errOut, code := crawl(srv.URL)
	if code != exitOK {
		t.Fatalf("without the proxy: exit %d\n%s", code, errOut)
	}
	via, errOut, code := crawl("http://"+proxy, "-no-map-guess")
	if code != exitOK || !strings.Contains(errOut, "-interact: ") {
		t.Errorf("through the proxy: exit %d, %d rows, proxy logged %d\n%s", code, len(via), logged(), errOut)
	}
	fwd, errOut, code := crawl(srv.URL, "-proxy", "http://"+proxy)
	if code != exitOK || !strings.Contains(errOut, "-interact: ") {
		t.Errorf("with -proxy: exit %d, %d rows, proxy logged %d\n%s", code, len(fwd), logged(), errOut)
	}
	for u := range direct {
		if !fwd[u] {
			t.Errorf("with -proxy the crawl lost %s", u)
		}
	}
	for u := range direct {
		if !via[u] {
			t.Errorf("behind the proxy the crawl lost %s", u)
		}
	}
	for _, route := range []string{"/api/fromscript", "/api/drawn", "/api/clicked"} {
		if !via[route] {
			t.Errorf("%s is not among the rows behind the proxy: %v", route, via)
		}
	}
}
