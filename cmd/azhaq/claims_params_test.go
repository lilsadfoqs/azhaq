package main

import (
	"encoding/json"
	"fmt"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// paramServer is a page that reads q (it lists a result for it) and counts
// what it is asked: the queries seen, in order, by path.
type paramServer struct {
	*httptest.Server
	mu      sync.Mutex
	queries []url.Values
	paths   map[string]int
}

func newParamServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *paramServer {
	t.Helper()
	s := &paramServer{paths: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.queries = append(s.queries, r.URL.Query())
		s.paths[r.URL.Path]++
		s.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		body := "<html><body>results"
		if r.URL.Query().Get("q") != "" {
			body += strings.Repeat(" <li>row</li>", 30)
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	t.Cleanup(s.Close)
	return s
}

func paramRows(t *testing.T, out string) []map[string]any {
	t.Helper()
	return jsonRows(t, out)
}

// params -json prints url, method, params, why and values and nothing else.
func TestParamsJSONPrintsOnlyItsFields(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := newParamServer(t, func(w http.ResponseWriter, r *http.Request) {
		body := "<html><body>results"
		if r.URL.Query().Get("q") != "" {
			body += strings.Repeat(" <li>row</li>", 30)
		}
		if r.URL.Query().Get("debug") == "true" {
			w.WriteHeader(500)
		}
		fmt.Fprint(w, body+"</body></html>")
	})
	words := wlist(t, "q", "debug", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10")
	out, _, code := runContract(t, "params", "-u", srv.URL+"/s", "-w", words, "-rate", "10000", "-db", "w.db")
	rows := paramRows(t, out)
	if code != exitOK || len(rows) != 1 {
		t.Fatalf("exit %d: %s", code, out)
	}
	allowed := map[string]bool{"url": true, "method": true, "params": true, "why": true, "values": true, "given": true}
	for k := range rows[0] {
		if !allowed[k] {
			t.Errorf("params -json printed %q: %v", k, rows[0])
		}
	}
	for _, k := range []string{"url", "method", "params", "why"} {
		if rows[0][k] == nil {
			t.Errorf("no %s in %v", k, rows[0])
		}
	}
	// The workspace row keeps the requests the page took, and show -json prints them.
	shown, _, err := captureBoth(t, func() error { return run([]string{"show", "-db", "w.db", "-json", srv.URL + "/s"}) })
	var sh struct {
		Observations []struct {
			Payload map[string]any `json:"payload"`
		} `json:"observations"`
	}
	if err != nil || json.Unmarshal([]byte(shown), &sh) != nil || len(sh.Observations) != 1 || sh.Observations[0].Payload["requests"] == nil || sh.Observations[0].Payload["writes"] != nil {
		t.Errorf("show: %v\n%s", err, shown)
	}
	// A body method keeps the number of body requests it sent as writes.
	if _, _, code := runContract(t, "params", "-u", srv.URL+"/s", "-w", words, "-X", "POST", "-rate", "10000", "-allow", "127.0.0.1", "-db", "p.db"); code != exitOK {
		t.Fatalf("-X POST: exit %d", code)
	}
	shown, _, err = captureBoth(t, func() error { return run([]string{"show", "-db", "p.db", "-json", srv.URL + "/s"}) })
	if err != nil || json.Unmarshal([]byte(shown), &sh) != nil || len(sh.Observations) == 0 || sh.Observations[0].Payload["writes"] == nil || sh.Observations[0].Payload["requests"] == nil {
		t.Errorf("show after -X POST: %v\n%s", err, shown)
	}
}

// The exit is 3 when every page failed and 0 when others gave their names;
// -strict-exit makes any failure 3. A page that limits requests is a failure
// listed as retryable with a note, and one that leaves requests unanswered is
// a failure with a note.
func TestParamsExitWhenAPageFails(t *testing.T) {
	t.Chdir(t.TempDir())
	var ws []string
	for i := 0; i < 300; i++ {
		ws = append(ws, fmt.Sprintf("name%d", i))
	}
	words := wlist(t, append(ws, "q")...)
	// A server of its own for each kind of failure: a host that limited requests is held back for a while.
	site := func(path string) *paramServer {
		var mu sync.Mutex
		n := 0
		return newParamServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/limited" && path == "/limited":
				mu.Lock()
				n++
				over := n > 2
				mu.Unlock()
				if over {
					w.Header().Set("Retry-After", "0")
					http.Error(w, "slow down", http.StatusTooManyRequests)
					return
				}
			case r.URL.Path == "/lost" && r.URL.Query().Has("name150"):
				c, _, _ := w.(http.Hijacker).Hijack()
				c.Close()
				return
			}
			body := "<html><body>results"
			if r.URL.Query().Get("q") != "" {
				body += strings.Repeat(" <li>row</li>", 30)
			}
			fmt.Fprint(w, body+"</body></html>")
		})
	}
	args := func(srv *paramServer, pages ...string) []string {
		a := []string{"params", "-w", words, "-rate", "10000", "-allow", "127.0.0.1"}
		for _, p := range pages {
			a = append(a, "-u", srv.URL+p)
		}
		return a
	}
	// A page that leaves requests unanswered (before the 429 block: the host's backoff outlives fetch.Reset).
	fetch.Reset()
	lost := site("/lost")
	out, rep, code := runContract(t, args(lost, "/ok", "/lost")...)
	if code != exitOK || !strings.Contains(out, `"params":["q"]`) || rep.Failures != 1 || len(rep.Failed) != 1 || rep.Failed[0].Retryable || !strings.Contains(strings.Join(rep.Notes, "\n"), "got no answer") {
		t.Errorf("one page lost requests, one gave its names: exit %d, failures %d, failed %+v, notes %q", code, rep.Failures, rep.Failed, rep.Notes)
	}
	fetch.Reset()
	if _, rep, code := runContract(t, append(args(lost, "/ok", "/lost"), "-strict-exit")...); code != exitPartial || rep.Failures != 1 {
		t.Errorf("-strict-exit: exit %d, failures %d", code, rep.Failures)
	}
	fetch.Reset()
	if _, rep, code := runContract(t, args(lost, "/lost")...); code != exitPartial || rep.Failures != 1 {
		t.Errorf("every page failed: exit %d, failures %d", code, rep.Failures)
	}
	// A page that limits requests (429): it waits out its backoff, 7 s, and fails.
	if !testing.Short() {
		fetch.Reset()
		out, rep, code := runContract(t, args(site("/limited"), "/ok", "/limited")...)
		if code != exitOK || !strings.Contains(out, `"params":["q"]`) || rep.Failures != 1 || len(rep.Failed) != 1 || !rep.Failed[0].Retryable {
			t.Errorf("one page limited, one gave its names: exit %d, failures %d, failed %+v\n%s", code, rep.Failures, rep.Failed, out)
		}
		if !strings.Contains(strings.Join(rep.Notes, "\n"), "not fully searched") {
			t.Errorf("notes %q", rep.Notes)
		}
	}
}

// A page that -deny-path matches is not searched, and the summary lists it
// under skipped with the rule; nothing is sent to it.
func TestParamsDenyPathPageIsNotSearchedAndSaysSo(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := newParamServer(t, nil)
	words := wlist(t, "q", "a1", "a2", "a3", "a4", "a5")
	out, rep, code := runContract(t, "params", "-u", srv.URL+"/secret/page", "-u", srv.URL+"/open", "-w", words, "-rate", "10000", "-allow", "127.0.0.1", "-deny-path", "^/secret")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d", code)
	}
	srv.mu.Lock()
	secret, open := srv.paths["/secret/page"], srv.paths["/open"]
	srv.mu.Unlock()
	if secret != 0 || open == 0 {
		t.Errorf("/secret/page was sent %d requests, /open %d: %s", secret, open, out)
	}
	if len(rep.Skipped) != 1 || !strings.HasSuffix(rep.Skipped[0].Target, "/secret/page") || rep.Skipped[0].Reason != "-deny-path ^/secret" {
		t.Errorf("the summary does not list the page with the rule: skipped %+v, notes %q", rep.Skipped, rep.Notes)
	}
}

// A page that is not text is not searched, and a note says why; neither is a
// page past -params-per-host.
func TestParamsDoesNotSearchAPageThatIsNotTextOrIsPastPerHost(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := newParamServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/image" {
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("\x89PNG"))
			return
		}
		fmt.Fprint(w, "<html><body>page "+r.URL.Path+"</body></html>")
	})
	words := wlist(t, "q", "a1", "a2", "a3", "a4", "a5")
	_, rep, _ := runContract(t, "params", "-u", srv.URL+"/image", "-w", words, "-rate", "10000", "-allow", "127.0.0.1")
	if got := strings.Join(rep.Notes, "\n"); !strings.Contains(got, "/image: not searched, the page is not text, HTML, JSON or XML (image/png)") {
		t.Errorf("a page that is not text: notes %q", rep.Notes)
	}
	// run -params: only the first page of a host is searched with -params-per-host 1.
	words2 := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(words2, []byte("q\na1\na2\na3\na4\na5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	site := newParamServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>`+r.URL.Path+`</body></html>`)
	})
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", site.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-params", words2, "-params-all", "-params-per-host", "1", "-json", "-quiet", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if got := strings.Join(lastReport(t, errOut).Notes, "\n"); !strings.Contains(got, "not searched, 1 pages of ") || !strings.Contains(got, "(-params-per-host)") {
		t.Errorf("notes %q", got)
	}
}

// Names are sent in the order given, without duplicates, every one, with a
// session or without one.
func TestParamsSendsEveryNameOnceInTheOrderGiven(t *testing.T) {
	var ws []string
	for i := 0; i < 80; i++ {
		ws = append(ws, fmt.Sprintf("n%02d", i))
	}
	given := append(append([]string{"cookie", "authorization", "session", "token"}, ws...), "n05", "cookie", "n79")
	var distinct []string
	seen := map[string]bool{}
	for _, n := range given {
		if !seen[n] {
			seen[n] = true
			distinct = append(distinct, n)
		}
	}
	for _, session := range []bool{false, true} {
		t.Run(fmt.Sprint("session=", session), func(t *testing.T) {
			t.Chdir(t.TempDir())
			var mu sync.Mutex
			var order []string // the names of the list, as the requests carried them
			srv := newParamServer(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				for _, kv := range strings.Split(r.URL.RawQuery, "&") {
					if n, _, _ := strings.Cut(kv, "="); seen[n] {
						order = append(order, n)
					}
				}
				mu.Unlock()
				fmt.Fprint(w, "<html><body>same</body></html>")
			})
			args := []string{"params", "-u", srv.URL + "/p", "-w", wlist(t, given...), "-rate", "10000", "-t", "1", "-allow", "127.0.0.1"}
			if session {
				args = append(args, "-cookie", "sid=abc", "-H", "Authorization: Bearer x")
			}
			runContract(t, args...)
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(order, distinct) {
				t.Errorf("the names were sent as %v, want the list in its order, each once: %v", order, distinct)
			}
		})
	}
}

// In run -params a page that answered the run's own request with 405 (as one
// that refused it with 401 or 403) is not searched; azhaq params asks every
// page it is given, and a page that answers names it does not read is listed
// in the summary's notes.
func TestRunParamsSkipsA405AndParamsAsksEveryPageGiven(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := newParamServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/m405":
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "method not allowed")
		case "/denied":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "no session")
		case "/echo": // every name is printed
			fmt.Fprint(w, "<html><body>")
			for k := range r.URL.Query() {
				if !strings.HasPrefix(k, "~") && !strings.HasPrefix(k, "az") {
					fmt.Fprintf(w, "<p>unknown parameter %s</p>\n", k)
				}
			}
			fmt.Fprint(w, "</body></html>")
		default:
			fmt.Fprint(w, `<html><body><a href="/m405">a</a><a href="/denied">b</a><a href="/echo">c</a></body></html>`)
		}
	})
	var ws []string
	for i := 0; i < 60; i++ {
		ws = append(ws, fmt.Sprintf("name%d", i))
	}
	words := wlist(t, ws...)
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-params", words, "-json", "-quiet", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatalf("%v\n%s", err, errOut)
	}
	srv.mu.Lock()
	m405, denied := srv.paths["/m405"], srv.paths["/denied"]
	srv.mu.Unlock()
	if m405 > 2 || denied > 2 {
		t.Errorf("run -params sent %d requests to the 405 page and %d to the 401 page: they were searched", m405, denied)
	}
	// azhaq params asks them all.
	for _, p := range []string{"/m405", "/denied"} {
		srv.mu.Lock()
		before := srv.paths[p]
		srv.mu.Unlock()
		runContract(t, "params", "-u", srv.URL+p, "-w", words, "-rate", "10000")
		srv.mu.Lock()
		if srv.paths[p]-before < 4 {
			t.Errorf("params -u %s was sent %d requests: it was not searched", p, srv.paths[p]-before)
		}
		srv.mu.Unlock()
	}
	_, rep, _ := runContract(t, "params", "-u", srv.URL+"/echo", "-w", words, "-rate", "10000")
	if got := strings.Join(rep.Notes, "\n"); !strings.Contains(got, "/echo answers names it does not read") {
		t.Errorf("notes %q", rep.Notes)
	}
}
