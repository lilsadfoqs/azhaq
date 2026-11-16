package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

const pyServer = "BaseHTTP/0.6 Python/3.14.4"

// headerProxy is a forward proxy for plain HTTP. Its own page (a request
// addressed to it) says Server: pyServer. With add it puts that header on
// every answer it forwards, as a logging proxy does; without, it passes the
// target's headers through. With refuse it hangs up on a request addressed to it.
type headerProxy struct {
	*httptest.Server
	mu     sync.Mutex
	direct int
}

func newHeaderProxy(t *testing.T, add, refuse bool) *headerProxy {
	t.Helper()
	p := &headerProxy{}
	tr := &http.Transport{Proxy: nil}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "" {
			p.mu.Lock()
			p.direct++
			p.mu.Unlock()
			if refuse {
				c, _, _ := w.(http.Hijacker).Hijack()
				c.Close()
				return
			}
			w.Header().Set("Server", pyServer)
			io.WriteString(w, "proxy page")
			return
		}
		out, _ := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			w.Header()[k] = vs
		}
		if add {
			w.Header().Set("Server", pyServer)
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *headerProxy) asked() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.direct
}

func headerTarget(t *testing.T, server string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		io.WriteString(w, "target page")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ledgerOf(t *testing.T) (read func() []ledger.Entry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil) })
	return func() []ledger.Entry {
		l.Close()
		var es []ledger.Entry
		_ = ledger.Read(path, func(e ledger.Entry) error {
			if e.Kind != ledger.KindSeal {
				es = append(es, e)
			}
			return nil
		})
		return es
	}
}

func getVia(t *testing.T, px *headerProxy, target string, n int) []http.Header {
	t.Helper()
	pu, _ := url.Parse(px.URL)
	SetTargetProxy(pu)
	c := TargetClient(TargetOptions{Timeout: 5 * time.Second})
	var out []http.Header
	for i := 0; i < n; i++ {
		resp, err := c.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out = append(out, resp.Header)
	}
	return out
}

// A header the proxy adds is learned from its own answer, asked once and
// recorded apart from the targets', and is not the target's.
func TestAProxyAddedHeaderIsNotTheTargets(t *testing.T) {
	Reset()
	defer Reset()
	read := ledgerOf(t)
	px := newHeaderProxy(t, true, false)
	srv := headerTarget(t, "")
	// The target's name is in scope, the proxy's address is not: asking the
	// proxy is not a request to a target.
	SetScope(func(h string) bool { return h == "localhost" })
	target := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	hs := getVia(t, px, target, 3)
	for i, h := range hs {
		if got := h.Get("Server"); got != "" {
			t.Errorf("answer %d: Server %q, want the proxy's own value dropped", i, got)
		}
	}
	if px.asked() != 1 {
		t.Errorf("the proxy was asked %d times for its own answer, want once", px.asked())
	}
	var proxyLines, targetLines int
	for _, e := range read() {
		switch {
		case e.Class == ledger.ClassProxy:
			proxyLines++
			if e.Target != px.URL+"/" || e.Method != "GET" {
				t.Errorf("proxy line %+v", e)
			}
		case e.IsTarget():
			targetLines++
		}
	}
	if proxyLines != 1 || targetLines != 3 {
		t.Errorf("ledger holds %d proxy lines and %d target lines, want 1 and 3", proxyLines, targetLines)
	}
	notes := strings.Join(ProxyNotes(), "\n")
	if !strings.Contains(notes, "3 of 3 answers carried a Server header equal to the proxy's own") || !strings.Contains(notes, pyServer) {
		t.Errorf("notes %q", notes)
	}
	if ProxyUnasked() {
		t.Error("the proxy was asked")
	}
}

// The target's own header, which the proxy passes through, is not the proxy's.
func TestATargetsOwnHeaderThroughAProxyStays(t *testing.T) {
	Reset()
	defer Reset()
	px := newHeaderProxy(t, false, false)
	srv := headerTarget(t, "nginx/1.25.3")
	hs := getVia(t, px, srv.URL, 2)
	for i, h := range hs {
		if got := h.Get("Server"); got != "nginx/1.25.3" {
			t.Errorf("answer %d: Server %q, want nginx/1.25.3", i, got)
		}
	}
	if n := ProxyNotes(); len(n) != 0 {
		t.Errorf("notes %q for a run that dropped nothing", n)
	}
}

// A proxy that refuses a request addressed to it is not asked in vain twice,
// says so, and nothing is dropped or trusted silently.
func TestAProxyThatRefusesIsSaidSo(t *testing.T) {
	Reset()
	defer Reset()
	px := newHeaderProxy(t, true, true)
	srv := headerTarget(t, "")
	hs := getVia(t, px, srv.URL, 2)
	if got := hs[0].Get("Server"); got != pyServer {
		t.Errorf("Server %q: without the proxy's own answer nothing is dropped", got)
	}
	if px.asked() != 1 {
		t.Errorf("asked %d times, want once", px.asked())
	}
	if !ProxyUnasked() {
		t.Error("ProxyUnasked is false for a proxy that refused")
	}
	if n := ProxyNotes(); len(n) != 1 || !strings.Contains(n[0], "could not be asked for its own answer") {
		t.Errorf("notes %q", n)
	}
}

// Only the values the proxy showed go: a target's own line stays beside them.
func TestOnlyTheProxysValueIsDropped(t *testing.T) {
	p := New(Config{})
	p.px.asked, p.px.host = true, "127.0.0.1:1"
	p.px.own = http.Header{"Server": {pyServer}, "Set-Cookie": {"px=1"}}
	h := http.Header{"Server": {pyServer, "nginx/1.25.3"}, "Set-Cookie": {"px=1", "sid=abc"}, "X-Cache": {"HIT"}, "Content-Type": {"text/html"}}
	p.dropProxyOwn(h)
	if got := h.Values("Server"); len(got) != 1 || got[0] != "nginx/1.25.3" {
		t.Errorf("Server %q", got)
	}
	if got := h.Values("Set-Cookie"); len(got) != 1 || got[0] != "sid=abc" {
		t.Errorf("Set-Cookie %q", got)
	}
	if h.Get("X-Cache") != "HIT" || h.Get("Content-Type") != "text/html" {
		t.Errorf("a header the proxy did not show was touched: %v", h)
	}
}

func TestIdentityHeaders(t *testing.T) {
	for name, want := range map[string]bool{"server": true, "X-Powered-By": true, "via": true, "Set-Cookie": true, "X-Cache": true,
		"X-Frame-Options": false, "Content-Type": false, "Location": false, "Date": false} {
		if got := IdentityHeader(name); got != want {
			t.Errorf("IdentityHeader(%q) = %v", name, got)
		}
	}
	h := WithoutIdentity(http.Header{"Server": {"x"}, "Content-Type": {"text/html"}})
	if len(h) != 1 || h.Get("Content-Type") == "" {
		t.Errorf("%v", h)
	}
}

// A proxy in reverse mode answers a request addressed to it with the target's
// own page: that answer is the "proxy's own", so the target's header equal to
// it is dropped and the note says so, not hidden.
func TestAReverseProxyShowsTheTargetsHeadersAsItsOwn(t *testing.T) {
	Reset()
	defer Reset()
	srv := headerTarget(t, "nginx/1.25.3")
	u, _ := url.Parse(srv.URL)
	rev := httptest.NewServer(httputil.NewSingleHostReverseProxy(u))
	defer rev.Close()
	hs := getVia(t, &headerProxy{Server: rev}, srv.URL, 1)
	if got := hs[0].Get("Server"); got != "" {
		t.Errorf("Server %q: equal to the proxy's own answer, it is dropped", got)
	}
	if n := ProxyNotes(); len(n) != 1 || !strings.Contains(n[0], "1 of 1 answers carried a Server header equal to the proxy's own") {
		t.Errorf("notes %q", n)
	}
}
