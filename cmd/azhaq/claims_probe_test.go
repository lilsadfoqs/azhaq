package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every target given ends as a row, a failure (a row with failed: true) or a
// skip (named under skipped in the summary, and sent nothing).
func TestProbeEveryTargetEndsAsARowAFailureOrASkip(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	out, rep, code := runContract(t, "probe", "-u", site.URL+"/api", "-u", "127.0.0.1:1", "-u", "http://other.example.org/", "-allow", "127.0.0.1")
	rows := probeRows(t, out)
	if code != exitOK || len(rows) != 2 {
		t.Fatalf("exit %d, rows %s", code, out)
	}
	byInput := map[string]map[string]any{}
	for _, r := range rows {
		byInput[r["input"].(string)] = r
	}
	if byInput[site.URL+"/api"]["failed"] != false || byInput["127.0.0.1:1"]["failed"] != true {
		t.Errorf("rows %v", byInput)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Target != "http://other.example.org/" || rep.Skipped[0].Reason != "outside the scope" {
		t.Errorf("skipped %+v", rep.Skipped)
	}
	if site.count() != 1 {
		t.Errorf("the site was sent %d requests", site.count())
	}
}

// An answered row always has input, host, host_ip, time, timestamp, url, port,
// scheme, path, method, status_code, content_length, words, lines and failed;
// a failed row has input, host, url, port, scheme, timestamp, failed and
// error.
func TestProbeRowsAlwaysHaveTheirFields(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	out, _, _ := runContract(t, "probe", "-u", site.URL+"/api", "-u", site.URL+"/missing", "-u", site.URL+"/home", "-u", "127.0.0.1:1")
	always := []string{"input", "host", "host_ip", "time", "timestamp", "url", "port", "scheme", "path", "method", "status_code", "content_length", "words", "lines", "failed"}
	failedHas := []string{"input", "host", "url", "port", "scheme", "timestamp", "failed", "error"}
	for _, r := range probeRows(t, out) {
		want := always
		if r["failed"] == true {
			want = failedHas
		}
		for _, k := range want {
			if _, ok := r[k]; !ok {
				var have []string
				for k := range r {
					have = append(have, k)
				}
				sort.Strings(have)
				t.Errorf("row of %v lacks %s: has %v", r["input"], k, have)
			}
		}
	}
}

// A default run sends GET and nothing else, whatever else it reads; other
// methods go out with -x, and your own request with -request.
func TestProbeSendsOnlyGETUnlessAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	runContract(t, "probe", "-u", site.URL+"/", "-u", site.URL+"/api", "-fr", "-favicon", "-title", "-td", "-hash", "md5")
	if site.count() == 0 {
		t.Fatal("nothing was sent")
	}
	for _, s := range site.seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("a default run sent %q", s)
		}
	}
	site.mu.Lock()
	site.seen = nil
	site.mu.Unlock()
	runContract(t, "probe", "-u", site.URL+"/api", "-x", "GET,PUT")
	if got := strings.Join(site.seen, ";"); !strings.Contains(got, "PUT /api") || !strings.Contains(got, "GET /api") {
		t.Errorf("-x GET,PUT sent %v", site.seen)
	}
	site.mu.Lock()
	site.seen = nil
	site.mu.Unlock()
	file := filepath.Join(t.TempDir(), "req.txt")
	if err := os.WriteFile(file, []byte("DELETE /api HTTP/1.1\r\nHost: x\r\n\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, rep, _ := runContract(t, "probe", "-u", site.URL, "-request", file)
	if len(site.seen) != 1 || site.seen[0] != "DELETE /api" || !strings.Contains(strings.Join(rep.Notes, " "), "can change data") {
		t.Errorf("-request sent %v, notes %v", site.seen, rep.Notes)
	}
}

// The summary says how many rows the matchers and filters left out, and counts
// the targets that got no answer.
func TestProbeSummaryCountsWhatTheFiltersLeftOutAndWhatGotNoAnswer(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	_, rep, _ := runContract(t, "probe", "-u", site.URL+"/home", "-u", site.URL+"/api", "-u", site.URL+"/missing", "-u", "127.0.0.1:1", "-mc", "200")
	if got := strings.Join(rep.Notes, "\n"); !strings.Contains(got, "-mc left out 1 answers that did not match") {
		t.Errorf("notes %q", rep.Notes)
	}
	if rep.Counts["without an answer"] != 1 {
		t.Errorf("counts %v", rep.Counts)
	}
}

// A plain request answered 400 stays 400 when TLS does not answer; a TLS
// request that is not answered is asked again over plain HTTP.
func TestProbeKeepsA400AndFallsBackFromTLSToPlain(t *testing.T) {
	t.Chdir(t.TempDir())
	// 400 to plain requests, TLS connections closed.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b := make([]byte, 1)
				if _, err := c.Read(b); err != nil || b[0] == 0x16 {
					return
				}
				r := bufio.NewReader(io.MultiReader(strings.NewReader(string(b)), c))
				for {
					if l, err := r.ReadString('\n'); err != nil || l == "\r\n" {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}()
		}
	}()
	out, _, code := runContract(t, "probe", "-u", l.Addr().String())
	if rows := probeRows(t, out); len(rows) != 1 || rows[0]["status_code"] != float64(400) || rows[0]["failed"] == true || code != exitOK {
		t.Errorf("exit %d: %s", code, out)
	}
	// A port below 1024 asks TLS first; a proxy that tunnels to a plain server leaves that unanswered.
	site := newProbeSite(t)
	var connects, plain atomic.Int32
	rp := &httputil.ReverseProxy{Director: func(r *http.Request) { r.URL.Scheme, r.URL.Host = "http", strings.TrimPrefix(site.URL, "http://") }}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			plain.Add(1)
			rp.ServeHTTP(w, r)
			return
		}
		connects.Add(1)
		up, err := net.Dial("tcp", strings.TrimPrefix(site.URL, "http://"))
		if err != nil {
			http.Error(w, "no", http.StatusBadGateway)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		go func() { _, _ = io.Copy(conn, up); conn.Close() }()
	}))
	defer proxy.Close()
	resolvers := serveZone(t, fakeZone{a: map[string]string{"a.labtest.com": "192.0.2.1"}})
	out, _, code = runContract(t, "probe", "-u", "a.labtest.com:444", "-resolvers", resolvers, "-proxy", proxy.URL)
	rows := probeRows(t, out)
	if len(rows) != 1 || rows[0]["scheme"] != "http" || rows[0]["status_code"] != float64(302) || rows[0]["port"] != "444" || connects.Load() != 1 || plain.Load() != 1 || code != exitOK {
		t.Errorf("exit %d, TLS asked %d times, plain %d times: %s", code, connects.Load(), plain.Load(), out)
	}
}

// timedSite records when each path was first asked.
type timedSite struct {
	*httptest.Server
	mu sync.Mutex
	at map[string]time.Time
}

func newTimedSite(t *testing.T) *timedSite {
	t.Helper()
	s := &timedSite{at: map[string]time.Time{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if _, ok := s.at[r.URL.Path]; !ok {
			s.at[r.URL.Path] = time.Now()
		}
		s.mu.Unlock()
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/favicon.ico":
			http.NotFound(w, r)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<title>t</title>"))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *timedSite) when(path string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.at[path]
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// -rl paces services: a target's first request waits its turn, its favicon and
// redirects do not; -rate paces every request instead.
func TestProbeRLWaitsOnlyForAServicesFirstRequestAndRatePacesEveryRequest(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newTimedSite(t)
	runContract(t, "probe", "-u", site.URL+"/", "-u", site.URL+"/api", "-rl", "1", "-fr", "-favicon", "-t", "4")
	root, home, api, ico := site.when("/"), site.when("/home"), site.when("/api"), site.when("/favicon.ico")
	if root.IsZero() || home.IsZero() || api.IsZero() || ico.IsZero() {
		t.Fatalf("not every request was sent: / %v /home %v /api %v favicon %v", root, home, api, ico)
	}
	if gap := absDur(api.Sub(root)); gap < 800*time.Millisecond {
		t.Errorf("two services at -rl 1 were asked %s apart, want a second", gap)
	}
	if gap := home.Sub(root); gap < 0 || gap > 500*time.Millisecond {
		t.Errorf("the redirect was asked %s after its service's first request: it does not wait for a turn", gap)
	}
	if gap := absDur(ico.Sub(root)); gap > 1500*time.Millisecond && absDur(ico.Sub(api)) > 1500*time.Millisecond {
		t.Errorf("the favicon waited for a turn: asked %s after /", gap)
	}
	// -rate N paces the redirect too.
	other := newTimedSite(t)
	runContract(t, "probe", "-u", other.URL+"/", "-rate", "2", "-fr")
	if gap := other.when("/home").Sub(other.when("/")); gap < 350*time.Millisecond {
		t.Errorf("at -rate 2 the redirect was asked %s after the first request, want 500 ms", gap)
	}
}

// The second scheme of a service does not wait for a turn under -rl.
func TestProbeRLDoesNotMakeTheSecondSchemeWait(t *testing.T) {
	t.Chdir(t.TempDir())
	var mu sync.Mutex
	at := map[string][]time.Time{}
	serve := func(name string, closePlain bool) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				at[name] = append(at[name], time.Now())
				mu.Unlock()
				go func() {
					defer c.Close()
					_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
					b := make([]byte, 1)
					if _, err := c.Read(b); err != nil || b[0] == 0x16 || closePlain {
						return
					}
					r := bufio.NewReader(io.MultiReader(strings.NewReader(string(b)), c))
					for {
						if l, err := r.ReadString('\n'); err != nil || l == "\r\n" {
							break
						}
					}
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				}()
			}
		}()
		return l.Addr().String()
	}
	a, b := serve("a", true), serve("b", false) // a closes the plain request, so TLS is asked next
	runContract(t, "probe", "-u", a, "-u", b, "-rl", "1", "-t", "4")
	mu.Lock()
	defer mu.Unlock()
	if len(at["a"]) != 2 || len(at["b"]) != 1 {
		t.Fatalf("connections: a %d, b %d", len(at["a"]), len(at["b"]))
	}
	if gap := at["a"][1].Sub(at["a"][0]); gap > 500*time.Millisecond {
		t.Errorf("the second scheme was asked %s after the first: it waited for a turn", gap)
	}
	if gap := absDur(at["b"][0].Sub(at["a"][0])); gap < 800*time.Millisecond {
		t.Errorf("two services at -rl 1 were asked %s apart", gap)
	}
}

// A route that streams for ever is answered with its status at once, not when
// the request times out.
func TestProbeAnswersARouteThatNeverEnds(t *testing.T) {
	t.Chdir(t.TempDir())
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for {
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer srv.Close()
	defer close(done)
	t0 := time.Now()
	out, _, code := runContract(t, "probe", "-u", srv.URL+"/events", "-req-timeout", "30s")
	rows := probeRows(t, out)
	if code != exitOK || len(rows) != 1 || rows[0]["status_code"] != float64(200) || rows[0]["failed"] == true || time.Since(t0) > 6*time.Second {
		t.Errorf("exit %d after %s: %s", code, time.Since(t0), out)
	}
}

// -kb needs the classifier's model: without it the command is a usage error
// that says where to fetch it, and nothing is downloaded.
func TestProbeKBWithoutTheModelIsAUsageError(t *testing.T) {
	t.Chdir(t.TempDir())
	site := newProbeSite(t)
	t.Setenv("AZHAQ_DIT_MODEL", filepath.Join(t.TempDir(), "model.json"))
	caught := thirdPartyCatcher(t)
	before := site.count()
	for _, flag := range []string{"-kb", "-fpt", "-fep"} {
		args := []string{"probe", "-u", site.URL + "/home", flag}
		if flag != "-kb" {
			args = append(args, "x")
		}
		_, errOut, code := cli(t, args...)
		if code != exitUsage || !strings.Contains(errOut, "the page classifier's model is not at ") || !strings.Contains(errOut, "download https://") {
			t.Errorf("%s: exit %d\n%s", flag, code, errOut)
		}
	}
	if caught.Load() != 0 || site.count() != before {
		t.Errorf("%d requests to a third party and %d to the site", caught.Load(), site.count()-before)
	}
}

// A plain request that times out is asked again over TLS, as one that is
// refused or closed is.
func TestProbePlainRequestThatTimesOutIsAskedOverTLS(t *testing.T) {
	t.Chdir(t.TempDir())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var mu sync.Mutex
	var plain, tls int
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b := make([]byte, 1)
				if _, err := c.Read(b); err != nil {
					return
				}
				mu.Lock()
				if b[0] == 0x16 {
					tls++
				} else {
					plain++
				}
				mu.Unlock()
				<-time.After(3 * time.Second) // never answers
			}()
		}
	}()
	out, _, _ := runContract(t, "probe", "-u", l.Addr().String(), "-req-timeout", "500ms")
	mu.Lock()
	defer mu.Unlock()
	if plain != 1 || tls != 1 {
		t.Errorf("plain %d, TLS %d, want one of each: %s", plain, tls, out)
	}
}
