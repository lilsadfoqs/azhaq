package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// counting is a server that counts what reaches it.
func counting(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// withLedger puts a ledger in use and returns what it holds, as "kind/class", once read.
func withLedger(t *testing.T) func() []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil) })
	return func() []string {
		var got []string
		if err := ledger.Read(path, func(e ledger.Entry) error { got = append(got, e.Kind+"/"+e.Class); return nil }); err != nil {
			t.Fatal(err)
		}
		return got
	}
}

func get(c *http.Client, raw string, hdr ...string) error {
	req, _ := http.NewRequest("GET", raw, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func TestTargetClientRecordsAsATarget(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	if err := get(TargetClient(TargetOptions{}), srv.URL); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
	if got := entries(); len(got) != 1 || got[0] != "http/target" {
		t.Fatalf("ledger %v", got)
	}
}

// The URL's host, the Host header, a header that names a host and the
// server name the handshake asks for are all held to the scope before
// anything leaves.
func TestTargetClientRefusesWhatLeavesTheScope(t *testing.T) {
	srv, hits := counting(t)
	u, _ := url.Parse(srv.URL)
	for _, tc := range []struct {
		name string
		hdr  []string
		open map[string]bool
		want bool // refused
	}{
		{"in scope", nil, nil, false},
		{"Host header outside", []string{"Host", "secret.lab"}, nil, true},
		{"Host header with a port outside", []string{"Host", "secret.lab:8443"}, nil, true},
		{"X-Forwarded-Host outside", []string{"X-Forwarded-Host", "a.test, secret.lab"}, nil, true},
		{"X-Original-Host outside", []string{"X-Original-Host", "secret.lab"}, nil, true},
		{"Host header inside", []string{"Host", "inside.test"}, nil, false},
		{"a header the user typed is open", []string{"X-Forwarded-Host", "secret.lab"}, map[string]bool{"x-forwarded-host": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			Reset()
			defer Reset()
			Current().SetScope(func(h string) bool { return h == u.Hostname() || h == "inside.test" || h == "a.test" }, tc.open)
			before := hits.Load()
			err := get(TargetClient(TargetOptions{}), srv.URL, tc.hdr...)
			if tc.want != errors.Is(err, neterr.ErrOutOfScope) || (err != nil && !tc.want) {
				t.Fatalf("err %v, want refused %v", err, tc.want)
			}
			if sent := hits.Load() - before; (sent == 1) == tc.want {
				t.Fatalf("server saw %d requests, refused %v", sent, tc.want)
			}
		})
	}
}

func TestTargetClientRefusesAnOutOfScopeURLAndServerName(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	SetScope(func(h string) bool { return h == "inside.test" })
	if err := get(TargetClient(TargetOptions{}), srv.URL); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("a URL outside the scope: %v", err)
	}
	SetScope(func(h string) bool { return h == "127.0.0.1" })
	c := TargetClient(TargetOptions{TLS: tlsNamed("secret.lab")})
	if err := get(c, srv.URL); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("a server name outside the scope: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
}

func TestTargetClientStopsAtTheKillFileAndDenyPath(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	SetDenyPath(func(raw string) string {
		if u, _ := url.Parse(raw); u.Path == "/admin" {
			return "^/admin"
		}
		return ""
	})
	SetOnDenied(func(string, string) {})
	if err := get(TargetClient(TargetOptions{}), srv.URL+"/admin"); !errors.Is(err, neterr.ErrDenied) {
		t.Fatalf("a denied path: %v", err)
	}
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)() // the file is seen at once
	if err := get(TargetClient(TargetOptions{}), srv.URL+"/x"); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("with the kill file there: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
}

func TestTargetClientGoesThroughTheTargetProxy(t *testing.T) {
	Reset()
	defer Reset()
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy.Add(1)
		fmt.Fprint(w, "proxied")
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	SetTargetProxy(pu)
	if err := get(TargetClient(TargetOptions{}), "http://target.invalid/x"); err != nil || viaProxy.Load() != 1 {
		t.Fatalf("%v, %d through the proxy", err, viaProxy.Load())
	}
}

// A source is asked about the targets, not sent to them: the scope does not
// hold it, the kill file does, and the ledger lists it as a source.
func TestSourceClientIsRecordedAndKilledButNotScoped(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	SetScope(func(h string) bool { return h == "inside.test" })
	if err := get(SourceClient(SourceOptions{}), srv.URL); err != nil || hits.Load() != 1 {
		t.Fatalf("a source outside the target scope: %v, %d hits", err, hits.Load())
	}
	if got := entries(); len(got) != 1 || got[0] != "http/source" {
		t.Fatalf("ledger %v", got)
	}
	path := filepath.Join(t.TempDir(), "run.stop")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetKill(path)()
	if err := get(SourceClient(SourceOptions{}), srv.URL); !errors.Is(err, neterr.ErrKilled) {
		t.Fatalf("a source with the kill file there: %v", err)
	}
}

func TestOwnClientIsNotRecorded(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	if err := get(OwnClient(OwnOptions{}), srv.URL); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
	if got := entries(); len(got) != 0 {
		t.Fatalf("ledger %v", got)
	}
}

// A client someone else made (a test's, or one injected) is held to the
// same controls once egress takes it.
func TestTargetFromHoldsAForeignClient(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := counting(t)
	SetScope(func(h string) bool { return h == "inside.test" })
	c := TargetFrom(srv.Client())
	if err := get(c, srv.URL); !errors.Is(err, neterr.ErrOutOfScope) || hits.Load() != 0 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
	if TargetFrom(c) != c {
		t.Error("a held client is wrapped again")
	}
	SetScope(nil)
	if err := get(c, srv.URL); err != nil {
		t.Fatal(err)
	}
	if got := entries(); len(got) != 1 || got[0] != "http/target" {
		t.Fatalf("ledger %v", got)
	}
}

func TestPinnedConnectsToTheGivenAddress(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := counting(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	c := Pinned(TargetClient(TargetOptions{}), "127.0.0.1")
	if err := get(c, "http://pinned.invalid:"+port+"/"); err != nil || hits.Load() != 1 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
}

func TestDialTargetUsesTheRunsResolverAndTheScope(t *testing.T) {
	Reset()
	defer Reset()
	srv, _ := counting(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	SetResolver(func(_ context.Context, host string) []string {
		if host == "app.test" {
			return []string{"127.0.0.1"}
		}
		return nil
	})
	c, err := DialTarget(context.Background(), "tcp", "app.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	SetScope(func(h string) bool { return h == "other.test" })
	if _, err := DialTarget(context.Background(), "tcp", "app.test:"+port); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("outside the scope: %v", err)
	}
	// A proxy is not a target.
	c, err = DialProxy(context.Background(), "tcp", "app.test:"+port)
	if err != nil {
		t.Fatalf("a proxy under a scope: %v", err)
	}
	c.Close()
}

// redirecting answers /a with a redirect to /b, /b with one to /c.
func redirecting(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		case "/out":
			http.Redirect(w, r, "http://outside.test/", http.StatusFound)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestFollowedRedirectHopsAreCountedAndRecorded(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := redirecting(t)
	c := TargetClient(TargetOptions{Follow: true})
	if err := Spend(context.Background()); err != nil { // the sender counts the first request
		t.Fatal(err)
	}
	if err := get(c, srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	if got := entries(); hits.Load() != 3 || Sent() != 3 || len(got) != 3 {
		t.Fatalf("server %d, counted %d, ledger %v: want 3 each", hits.Load(), Sent(), got)
	}
}

func TestBudgetStopsAFollowedRedirect(t *testing.T) {
	for _, n := range []int64{1, 2, 3} {
		Reset()
		SetMaxRequests(n)
		srv, hits := redirecting(t)
		c := TargetClient(TargetOptions{Follow: true})
		if err := Spend(context.Background()); err != nil {
			t.Fatal(err)
		}
		err := get(c, srv.URL+"/a")
		if n < 3 && !errors.Is(err, neterr.ErrBudget) {
			t.Errorf("budget %d: error %v, want the budget's", n, err)
		}
		if hits.Load() != int32(n) || Sent() != n {
			t.Errorf("budget %d: server %d, counted %d", n, hits.Load(), Sent())
		}
	}
	Reset()
}

func TestRefusedRedirectHopIsNotCounted(t *testing.T) {
	Reset()
	defer Reset()
	srv, hits := redirecting(t)
	SetScope(func(h string) bool { return h == "127.0.0.1" })
	c := TargetClient(TargetOptions{Follow: true})
	if err := Spend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := get(c, srv.URL+"/out"); !errors.Is(err, neterr.ErrOutOfScope) {
		t.Fatalf("error %v, want out of scope", err)
	}
	if hits.Load() != 1 || Sent() != 1 {
		t.Errorf("server %d, counted %d, want 1 each", hits.Load(), Sent())
	}
}

// A request through an HTTP proxy names the URL's authority in its request
// line whatever its Host header says: the proxy goes where the URL says, and
// the Host header only picks the virtual host there (as curl -x does).
func TestProxiedRequestLineNamesTheURLNotTheHostHeader(t *testing.T) {
	Reset()
	defer Reset()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type seen struct{ line, host string }
	got := make(chan seen, 4)
	go func() { // a proxy that keeps the bytes as they came
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer cn.Close()
				br := bufio.NewReader(cn)
				var s seen
				for first := true; ; first = false {
					l, err := br.ReadString('\n')
					l = strings.TrimSpace(l)
					if err != nil || l == "" {
						break
					}
					if first {
						s.line = strings.TrimSuffix(l, " HTTP/1.1")
					} else if v, ok := strings.CutPrefix(l, "Host: "); ok {
						s.host = v
					}
				}
				got <- s
				fmt.Fprint(cn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}()
		}
	}()
	pu, _ := url.Parse("http://" + ln.Addr().String())
	SetTargetProxy(pu)
	c := TargetClient(TargetOptions{})
	for _, tc := range []struct {
		name, url, host, raw, line, wantHost string // raw is an Opaque path, as -raw sends
	}{
		{"another port in Host", "http://127.0.0.1:3001/a/b?x=1", "127.0.0.1:5002", "", "GET http://127.0.0.1:3001/a/b?x=1", "127.0.0.1:5002"},
		{"another name in Host", "http://127.0.0.1:3001/", "vhost.test", "", "GET http://127.0.0.1:3001/", "vhost.test"},
		{"no Host header", "http://127.0.0.1:3001/a", "", "", "GET http://127.0.0.1:3001/a", "127.0.0.1:3001"},
		{"raw path keeps its form", "http://127.0.0.1:3001/", "", "/a/../b%2f?q=1", "GET http://127.0.0.1:3001/a/../b%2f?q=1", "127.0.0.1:3001"},
	} {
		req, _ := http.NewRequest("GET", tc.url, nil)
		req.Host = tc.host
		if tc.raw != "" {
			req.URL.Opaque = tc.raw
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.Request.URL.Opaque != req.URL.Opaque || resp.Request.URL.Host != "127.0.0.1:3001" {
			t.Errorf("%s: the answer's request is not the one sent: %v", tc.name, resp.Request.URL)
		}
		if s := <-got; s.line != tc.line || s.host != tc.wantHost {
			t.Errorf("%s: the proxy saw %q with Host %q, want %q with %q", tc.name, s.line, s.host, tc.line, tc.wantHost)
		}
	}
}
