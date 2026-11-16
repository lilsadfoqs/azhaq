package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// allForwardProxy is a stand-in for a proxy that sends every request it gets,
// the one addressed to it included, to one upstream (bench/truth/ledger/
// countproxy.py does the same), and counts what it forwards.
type allForwardProxy struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newAllForwardProxy(t *testing.T, upstream *httptest.Server) *allForwardProxy {
	t.Helper()
	p := &allForwardProxy{}
	tr := &http.Transport{Proxy: nil}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.paths = append(p.paths, r.URL.RequestURI())
		p.mu.Unlock()
		out, _ := http.NewRequestWithContext(r.Context(), r.Method, upstream.URL+r.URL.RequestURI(), r.Body)
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
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *allForwardProxy) forwarded() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.paths)
}

// asks is how many times the proxy was asked for its own page: GET / is the
// only request the app below never gets.
func (p *allForwardProxy) asks() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.paths {
		if s == "/" {
			n++
		}
	}
	return n
}

// askApp answers a page with a form and every other path with a JSON body.
func askApp(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ledgerSplit is the lines of a ledger to targets and to the -proxy itself.
func ledgerSplit(t *testing.T, path string) (targets, proxy int) {
	t.Helper()
	if err := ledger.Read(path, func(e ledger.Entry) error {
		switch {
		case !e.Counted():
		case e.Class == ledger.ClassProxy:
			proxy++
		default:
			targets++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return targets, proxy
}

// The ask of the proxy reaches the target through a proxy that forwards it,
// so the summary, the ledger and the proxy's own count say the same.
func TestProxyAskIsCountedLikeATargetRequest(t *testing.T) {
	app := askApp(t)
	for _, tc := range []struct {
		name string
		args func(target, led string) []string
		cmd  func([]string) error
		max  int
	}{
		{"params -max-requests 1", func(target, led string) []string {
			return []string{"-u", target + "/users/v1/name1", "-w", wlist(t, "id", "q", "page"), "-max-requests", "1", "-ledger", led, "-json"}
		}, cmdParams, 1},
		{"params -max-requests 5", func(target, led string) []string {
			return []string{"-u", target + "/users/v1/name1", "-w", wlist(t, "id", "q", "page"), "-max-requests", "5", "-ledger", led, "-json"}
		}, cmdParams, 5},
		{"run -max-requests 9", func(target, led string) []string {
			return []string{"-url", target + "/app", "-db", filepath.Join(t.TempDir(), "w.db"), "-depth", "0", "-no-favicon",
				"-max-requests", "9", "-ledger", led, "-json"}
		}, cmdRun, 9},
		{"run", func(target, led string) []string {
			return []string{"-url", target + "/app", "-db", filepath.Join(t.TempDir(), "w.db"), "-depth", "0", "-no-favicon", "-no-paths",
				"-ledger", led, "-json"}
		}, cmdRun, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			egress.Reset()
			px := newAllForwardProxy(t, app)
			led := filepath.Join(t.TempDir(), "l.jsonl")
			args := append(tc.args(app.URL, led), "-proxy", px.URL)
			_, errOut, _ := captureBoth(t, func() error { return tc.cmd(args) })
			rep := lastReport(t, errOut)
			targets, proxy := ledgerSplit(t, led)
			if int(rep.Requests) != px.forwarded() || int(rep.Requests) != targets+proxy {
				t.Errorf("the summary counts %d requests, the proxy forwarded %d, the ledger holds %d to targets and %d to the proxy\n%s",
					rep.Requests, px.forwarded(), targets, proxy, errOut)
			}
			if tc.max > 0 && px.forwarded() > tc.max {
				t.Errorf("-max-requests %d: the proxy forwarded %d", tc.max, px.forwarded())
			}
			notes := strings.Join(rep.Notes, "\n")
			switch {
			case tc.max == 1:
				// The one request was the target's: the budget was spent before the ask.
				if px.asks() != 0 || proxy != 0 || !strings.Contains(notes, "budget was spent before it could be asked") {
					t.Errorf("asks %d, proxy lines %d, notes %q: with the budget spent the proxy is not asked, and the run says so", px.asks(), proxy, notes)
				}
			default:
				if px.asks() != 1 || proxy != 1 || !strings.Contains(notes, "1 request to the -proxy itself") {
					t.Errorf("asks %d, proxy lines %d, notes %q: want one ask, in the ledger and named", px.asks(), proxy, notes)
				}
			}
		})
	}
}

// roles asks the proxy once for the whole command, not once for each client.
func TestRolesReplayAsksTheProxyOnce(t *testing.T) {
	var mu sync.Mutex
	var seen int
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if user != "alice" && user != "bob" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"sign in"}`)
			return
		}
		fmt.Fprintf(w, `{"data":{"username":%q,"note":"what %s wrote"}}`, user, user)
	}))
	defer app.Close()
	px := newAllForwardProxy(t, app)
	browse := func(file, user string) string {
		tok := "Bearer tok-" + user
		at := func(m int) string { return fmt.Sprintf("2026-10-29T10:%02d:00.000Z", m) }
		return writeHAR(t, file,
			harEntry(at(0), "GET", app.URL+"/api/me", "", 200, "Authorization", tok),
			harEntry(at(1), "GET", app.URL+"/api/notes/"+user, "", 200, "Authorization", tok),
			harEntry(at(2), "GET", app.URL+"/api/notes/shared", "", 200, "Authorization", tok),
		)
	}
	dir := t.TempDir()
	_, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", dir, "-har", "alice=" + browse("alice.har", "alice"), "-har", "bob=" + browse("bob.har", "bob"), "-proxy", px.URL})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	targets, proxy := ledgerSplit(t, filepath.Join(dir, "roles.ledger.jsonl"))
	if px.asks() != 1 || proxy != 1 {
		t.Errorf("the proxy was asked %d times, the ledger holds %d lines to it: want one", px.asks(), proxy)
	}
	if int(rep.Requests) != px.forwarded() || int(rep.Requests) != targets+proxy {
		t.Errorf("the summary counts %d requests, the proxy forwarded %d, the ledger holds %d to targets and %d to the proxy",
			rep.Requests, px.forwarded(), targets, proxy)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "1 request to the -proxy itself") {
		t.Errorf("notes %q do not name the ask", rep.Notes)
	}
}

// plan names the ask in what it would send and in its estimate, for an HTTP
// proxy; a SOCKS5 proxy has no answer to ask for.
func TestPlanNamesTheProxyAsk(t *testing.T) {
	text, _, code := cli(t, "plan", "-url", "http://127.0.0.1:9/app", "-proxy", "http://127.0.0.1:8", "-sources", "none", "-no-favicon")
	if code != exitOK || !strings.Contains(text, "1 request to the -proxy itself") || !strings.Contains(text, "proxy        1 request") {
		t.Errorf("exit %d: the plan does not name the ask:\n%s", code, text)
	}
	text, _, _ = cli(t, "plan", "-url", "http://127.0.0.1:9/app", "-proxy", "socks5://127.0.0.1:8", "-sources", "none", "-no-favicon")
	if strings.Contains(text, "to the -proxy itself") {
		t.Errorf("a SOCKS5 proxy is not asked:\n%s", text)
	}
	text, _, _ = cli(t, "plan", "-url", "http://127.0.0.1:9/app", "-sources", "none", "-no-favicon")
	if strings.Contains(text, "to the -proxy itself") {
		t.Errorf("no -proxy, no ask:\n%s", text)
	}
}
