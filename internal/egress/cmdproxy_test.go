package egress

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// viaCmdProxy is a client that sends everything to the proxy, loopback too.
func viaCmdProxy(cp *CmdProxy) *http.Client {
	pu, _ := url.Parse("http://" + cp.Addr())
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func body(t *testing.T, c *http.Client, raw string) (int, string) {
	t.Helper()
	resp, err := c.Get(raw)
	if err != nil {
		t.Fatalf("GET %s: %v", raw, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// entries is what the ledger at path holds, as "METHOD target collector".
func ledgerLines(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	if err := ledger.Read(path, func(e ledger.Entry) error {
		out = append(out, e.Method+" "+e.Target+" "+e.Collector)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func openLedger(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil) })
	return path
}

// A plain request goes through the target client: the scope holds it, the
// ledger lists it with the role's name, and a request outside the scope is
// answered 403 with the reason, never sent, and kept as the sign-in's failure.
func TestCmdProxyListsAndHoldsPlainRequests(t *testing.T) {
	Reset()
	defer Reset()
	path := openLedger(t)
	in, inHits := counting(t)
	out, outHits := counting(t)
	inU, _ := url.Parse(in.URL)
	cp, err := StartCmdProxy("bob", CmdScope{AllowAddr: func(h, p string) bool { return h == "127.0.0.1" && p == inU.Port() }, Allow: func(h string) bool { return h == "127.0.0.1" }})
	if err != nil {
		t.Fatal(err)
	}
	c := viaCmdProxy(cp)
	if code, b := body(t, c, in.URL+"/login?u=bob"); code != 200 || b != "ok" || inHits.Load() != 1 {
		t.Fatalf("in scope: %d %q, %d hits", code, b, inHits.Load())
	}
	code, msg := body(t, c, out.URL+"/steal")
	if code != http.StatusForbidden || !strings.Contains(msg, "azhaq refused GET "+out.URL+"/steal") || !strings.Contains(msg, "outside the scope") || outHits.Load() != 0 {
		t.Fatalf("outside the scope: %d %q, %d hits", code, msg, outHits.Load())
	}
	cp.Close()
	if err := cp.Refused(); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Errorf("the refusal kept for the sign-in: %v", err)
	}
	if cp.Requests() != 1 {
		t.Errorf("requests %d, want the one that was sent", cp.Requests())
	}
	got := ledgerLines(t, path)
	want := "GET " + in.URL + "/login?u=bob role-cmd:bob"
	if len(got) != 1 || got[0] != want {
		t.Errorf("ledger %q, want [%q]", got, want)
	}
}

// HTTPS is a CONNECT: held by host and port, listed as CONNECT host:port, and
// the tunnel carries the bytes without the ledger reading them.
func TestCmdProxyTunnelsConnectAndListsIt(t *testing.T) {
	Reset()
	defer Reset()
	path := openLedger(t)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "inside") }))
	defer secure.Close()
	su, _ := url.Parse(secure.URL)
	cp, err := StartCmdProxy("bob", CmdScope{Allow: func(h string) bool { return h == "127.0.0.1" }, AllowAddr: func(h, p string) bool { return h == "127.0.0.1" && p == su.Port() }})
	if err != nil {
		t.Fatal(err)
	}
	c := viaCmdProxy(cp)
	if code, b := body(t, c, secure.URL+"/token"); code != 200 || b != "inside" {
		t.Fatalf("through the tunnel: %d %q", code, b)
	}
	// Another port of the same host is refused by port.
	other, _ := counting(t)
	ou, _ := url.Parse(other.URL)
	if _, err := c.Get("https://127.0.0.1:" + ou.Port() + "/"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("a CONNECT to a port outside the scope: %v", err)
	}
	cp.Close()
	got := ledgerLines(t, path)
	if len(got) != 1 || got[0] != "CONNECT 127.0.0.1:"+su.Port()+" role-cmd:bob" {
		t.Errorf("ledger %q", got)
	}
	if !errors.Is(cp.Refused(), neterr.ErrOutOfScope) || !strings.Contains(cp.Refused().Error(), "CONNECT 127.0.0.1:"+ou.Port()) {
		t.Errorf("refusal %v", cp.Refused())
	}
}

// The budget the command is given holds: the request after it is spent is
// answered 429 with the reason, and the sign-in's failure is the budget's.
func TestCmdProxyBudgetRefusesTheNextRequest(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	cp, err := StartCmdProxy("bob", CmdScope{Capped: true, Left: 2})
	if err != nil {
		t.Fatal(err)
	}
	c := viaCmdProxy(cp)
	for i := 0; i < 2; i++ {
		if code, _ := body(t, c, srv.URL+"/"); code != 200 {
			t.Fatalf("request %d: %d", i+1, code)
		}
	}
	code, msg := body(t, c, srv.URL+"/")
	cp.Close()
	if code != http.StatusTooManyRequests || !strings.Contains(msg, "the request budget is spent") || hits.Load() != 2 {
		t.Fatalf("third request: %d %q, %d hits", code, msg, hits.Load())
	}
	if !errors.Is(cp.Refused(), neterr.ErrBudget) {
		t.Errorf("refusal %v", cp.Refused())
	}
	// Nothing left before it starts: every request is refused.
	cp, _ = StartCmdProxy("bob", CmdScope{Capped: true, Left: 0})
	if code, _ := body(t, viaCmdProxy(cp), srv.URL+"/"); code != http.StatusTooManyRequests || hits.Load() != 2 {
		t.Errorf("with the budget spent: %d, %d hits", code, hits.Load())
	}
	cp.Close()
}

// The proxy's variables replace the environment's, NO_PROXY is empty, and
// the scope the policy had comes back when the proxy closes.
func TestCmdProxyEnvAndRestore(t *testing.T) {
	Reset()
	defer Reset()
	SetScope(func(h string) bool { return h == "before.test" })
	cp, err := StartCmdProxy("bob", CmdScope{})
	if err != nil {
		t.Fatal(err)
	}
	if !Allows("anything.test") {
		t.Error("the command's own scope (none) is not in force while it runs")
	}
	env := cp.Env([]string{"PATH=/bin", "http_proxy=http://old:1", "NO_PROXY=127.0.0.1,localhost", "HTTPS_PROXY=http://old:2", "KEEP=1"})
	cp.Close()
	if Allows("anything.test") || !Allows("before.test") {
		t.Error("the scope the run had is not back")
	}
	u := "http://" + cp.Addr()
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if !slices.Contains(env, k+"="+u) {
			t.Errorf("%s is not set to the proxy: %v", k, env)
		}
	}
	for _, kv := range env {
		if strings.Contains(kv, "old:") || strings.Contains(kv, "localhost") {
			t.Errorf("the environment's own proxy setting stayed: %s", kv)
		}
	}
	if !slices.Contains(env, "NO_PROXY=") || !slices.Contains(env, "no_proxy=") || !slices.Contains(env, "PATH=/bin") || !slices.Contains(env, "KEEP=1") {
		t.Errorf("env %v", env)
	}
}

// The kill file stops the proxy's requests with 503 and the reason, and -proxy
// carries the ones that go: the command's request is the run's, not a path round it.
func TestCmdProxyStopsAtTheKillFileAndGoesThroughTheTargetProxy(t *testing.T) {
	Reset()
	defer Reset()
	var viaProxy atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "" { // the run's one request to the proxy itself, for its own answer
			return
		}
		viaProxy.Add(1)
		fmt.Fprint(w, "proxied")
	}))
	defer up.Close()
	pu, _ := url.Parse(up.URL)
	SetTargetProxy(pu)
	cp, err := StartCmdProxy("bob", CmdScope{})
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	c := viaCmdProxy(cp)
	if code, b := body(t, c, "http://target.invalid/x"); code != 200 || b != "proxied" || viaProxy.Load() != 1 {
		t.Fatalf("through -proxy: %d %q, %d at the proxy", code, b, viaProxy.Load())
	}
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)()
	code, msg := body(t, c, "http://target.invalid/y")
	if code != http.StatusServiceUnavailable || !strings.Contains(msg, "kill file") || viaProxy.Load() != 1 {
		t.Fatalf("with the kill file: %d %q, %d at the proxy", code, msg, viaProxy.Load())
	}
}
