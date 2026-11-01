package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// loginTarget is a form with a one-use token, and a login that checks it.
func loginTarget(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	issued := map[string]bool{}
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			n++
			tok := fmt.Sprintf("tok%d", n)
			issued[tok] = true
			fmt.Fprintf(w, `<input name="user_token" value="%s">`, tok)
			return
		}
		b, _ := io.ReadAll(r.Body)
		form := string(b)
		tok := form[strings.LastIndex(form, "user_token=")+len("user_token="):]
		ok := strings.Contains(form, "password=pw7&") && issued[tok]
		delete(issued, tok)
		loc := "login.php"
		if ok {
			loc = "index.php"
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// closingProxy forwards to the target and drops each connection after its
// answer, without saying so: it counts what it was asked.
func closingProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	fwd := &http.Client{Transport: &http.Transport{Proxy: nil}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		out, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		out.Header = r.Header.Clone()
		resp, err := fwd.Do(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateIdle {
			c.Close()
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &hits
}

// ledgerHTTP is how many http lines the ledger holds.
func ledgerHTTP(t *testing.T, path string) int {
	t.Helper()
	n := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "http" {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func fuzzWithFlights(t *testing.T, target *httptest.Server, proxy, ledgerPath string) report {
	t.Helper()
	dir := t.TempDir()
	pre, post := filepath.Join(dir, "pre.req"), filepath.Join(dir, "post.req")
	os.WriteFile(pre, []byte("GET /login.php HTTP/1.1\n\n"), 0o644)
	os.WriteFile(post, []byte("GET /logout.php HTTP/1.1\n\n"), 0o644)
	var words []string
	for i := 0; i < 60; i++ {
		words = append(words, fmt.Sprintf("pw%d", i))
	}
	_, rep, _ := fuzzRows(t, "-u", target.URL+"/login.php", "-X", "POST", "-d", "username=admin&password=FUZZ&Login=Login&user_token=TOKEN",
		"-w", wlist(t, words...), "-t", "8", "-ac=false", "-mr", "Location: index.php", "-x", proxy, "-ledger", ledgerPath,
		"-preflight", pre, "-preflight-var-auto", "TOKEN:form:user_token", "-postflight", post)
	return rep
}

// The ledger and the summary hold the requests that reached the proxy, no
// more: a request written to a connection the proxy had closed is made again
// on a new one, and is one request.
func TestFuzzFlightsLedgerAndCountEqualWhatAProxyAnswered(t *testing.T) {
	target := loginTarget(t)
	proxy, hits := closingProxy(t)
	ledgerPath := filepath.Join(t.TempDir(), "l.jsonl")
	rep := fuzzWithFlights(t, target, proxy.URL, ledgerPath)
	if len(rep.Failed) != 0 {
		t.Errorf("failed %+v", rep.Failed)
	}
	if want := int(hits.Load()); int(rep.Requests) != want || ledgerHTTP(t, ledgerPath) != want {
		t.Errorf("the proxy answered %d requests, the summary says %d, the ledger holds %d", want, rep.Requests, ledgerHTTP(t, ledgerPath))
	}
}

// The same with the independent counting proxy the ledger is checked against.
func TestFuzzFlightsLedgerAndCountEqualCountproxy(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	script, _ := filepath.Abs("../../bench/truth/ledger/countproxy.py")
	target := loginTarget(t)
	tport := target.Listener.Addr().(*net.TCPAddr).Port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pport := l.Addr().(*net.TCPAddr).Port
	l.Close()
	dir := t.TempDir()
	log := filepath.Join(dir, "proxy.jsonl")
	cmd := exec.Command(py, "-I", script, fmt.Sprint(pport), fmt.Sprint(tport), log)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pport))
		if err == nil {
			c.Close()
			break
		}
		if i > 100 {
			t.Fatal("countproxy did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	ledgerPath := filepath.Join(dir, "l.jsonl")
	rep := fuzzWithFlights(t, target, fmt.Sprintf("http://127.0.0.1:%d", pport), ledgerPath)
	got := 0
	if f, err := os.Open(log); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			got++
		}
		f.Close()
	}
	if int(rep.Requests) != got || ledgerHTTP(t, ledgerPath) != got {
		t.Errorf("countproxy saw %d requests, the summary says %d, the ledger holds %d", got, rep.Requests, ledgerHTTP(t, ledgerPath))
	}
}

// A redirect hop the run follows (-r) is a request: it is in the budget, the
// summary and the ledger, as it is at the proxy.
func TestFuzzFollowedRedirectIsCountedAndCapped(t *testing.T) {
	target := loginTarget(t)
	var hits atomic.Int32
	fwd := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		out, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
		out.Header = r.Header.Clone()
		resp, err := fwd.Do(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	run := func(max string) (report, string, error) {
		ledgerPath := filepath.Join(t.TempDir(), "l.jsonl")
		_, rep, err := fuzzRows(t, "-u", target.URL+"/FUZZ", "-X", "POST", "-d", "password=pw7&user_token=x", "-w", wlist(t, "login"), "-r", "-ac=false",
			"-x", proxy.URL, "-ledger", ledgerPath, "-max-requests", max)
		return rep, ledgerPath, err
	}
	hits.Store(0)
	rep, lp, err := run("0")
	if err != nil || hits.Load() != 2 || rep.Requests != 2 || ledgerHTTP(t, lp) != 2 {
		t.Errorf("proxy %d, summary %d, ledger %d, err %v: want 2 each", hits.Load(), rep.Requests, ledgerHTTP(t, lp), err)
	}
	hits.Store(0)
	rep, lp, err = run("1")
	if exitCode(err) != exitLimit || hits.Load() != 1 || rep.Requests != 1 || ledgerHTTP(t, lp) != 1 {
		t.Errorf("budget 1: exit %d, proxy %d, summary %d, ledger %d: want 1 each", exitCode(err), hits.Load(), rep.Requests, ledgerHTTP(t, lp))
	}
}
