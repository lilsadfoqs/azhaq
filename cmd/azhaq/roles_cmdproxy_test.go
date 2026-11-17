package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
)

// proxyCmdHelper is the test binary run as a -role-cmd command (TestMain, with
// AZHAQ_TEST_AS_CMD=1): it sends what its arguments say through the proxy
// variables, prints each answer's status to stderr and exits 0 whatever the
// status, as curl -s does. Go's own client skips the proxy for loopback, so
// it reads http_proxy itself.
//
//	get URL...      GET each URL through the proxy
//	tls URL         GET an https URL: a CONNECT, then TLS inside the tunnel
//	connect H:P     CONNECT by hand and print the proxy's status line
//	direct URL...   GET each URL with no proxy: a tool that ignores the variables
func proxyCmdHelper(args []string) int {
	if len(args) >= 2 && args[0] == "direct" { // a request that skips the proxy variables
		c := &http.Client{Transport: &http.Transport{Proxy: nil}}
		for _, raw := range args[1:] {
			if resp, err := c.Get(raw); err == nil {
				resp.Body.Close()
			}
		}
		return 0
	}
	pu, err := url.Parse(os.Getenv("http_proxy"))
	if err != nil || pu.Host == "" {
		fmt.Fprintln(os.Stderr, "helper: no http_proxy")
		return 2
	}
	if len(args) < 2 {
		return 2
	}
	switch args[0] {
	case "get", "tls":
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		for _, raw := range args[1:] {
			resp, err := c.Get(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "helper: %s: %v\n", raw, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Fprintf(os.Stderr, "helper: %s status %d %s\n", raw, resp.StatusCode, strings.TrimSpace(string(body)))
		}
	case "connect":
		conn, err := net.Dial("tcp", pu.Host)
		if err != nil {
			return 2
		}
		defer conn.Close()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", args[1], args[1])
		line, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Fprintf(os.Stderr, "helper: %s status line %s", args[1], line)
	}
	return 0
}

// helperCmd is the shell line of a -role-cmd that runs the helper, then prints
// a token as a role's command does.
func helperCmd(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + a + "'"
	}
	return fmt.Sprintf("AZHAQ_TEST_AS_CMD=1 '%s' %s; echo 'Authorization: Bearer tok'", os.Args[0], strings.Join(q, " "))
}

type cmdProxyRun struct {
	dir     string
	rep     report
	errOut  string
	err     error
	entries []ledger.Entry
}

func runRolesCmd(t *testing.T, cmd string, pre []string, runOpts ...string) cmdProxyRun {
	t.Helper()
	return runRolesArgs(t, append([]string{"-role", "anon", "-role-cmd", "bob=" + cmd}, pre...), runOpts...)
}

// runRolesArgs runs roles with the given options, then -- and the run options.
func runRolesArgs(t *testing.T, opts []string, runOpts ...string) cmdProxyRun {
	t.Helper()
	dir := t.TempDir()
	args := append(append([]string{"-json", "-dir", dir}, opts...), "--")
	args = append(args, runOpts...)
	_, errOut, err := captureBoth(t, func() error { return cmdRoles(args) })
	r := cmdProxyRun{dir: dir, errOut: errOut, err: err, rep: lastReport(t, errOut)}
	_ = ledger.Read(filepath.Join(dir, "roles.ledger.jsonl"), func(e ledger.Entry) error {
		r.entries = append(r.entries, e)
		return nil
	})
	return r
}

func (r cmdProxyRun) counted() int64 {
	var n int64
	for _, e := range r.entries {
		if e.Counted() {
			n++
		}
	}
	return n
}

func (r cmdProxyRun) notes() string { return strings.Join(r.rep.Notes, "\n") }

// ports of the two loopback sites.
func cmdPortOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func countingSite(hits *atomic.Int64, paths *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/" && paths != nil {
			*paths = append(*paths, r.Method+" "+r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>home</title></html>`)
	}))
}

// The proxy gives the command's request to the run: a GET to the target goes
// out, and the ledger lists it with the role's name, as the same kind of line
// azhaq's own requests are, and the summary's requests count it.
func TestRoleCmdRequestIsInTheLedgerWithTheRolesName(t *testing.T) {
	var hits atomic.Int64
	var paths []string
	site := countingSite(&hits, &paths)
	defer site.Close()
	r := runRolesCmd(t, helperCmd("get", site.URL+"/signin?u=bob"), nil, "-url", site.URL+"/", "-no-paths")
	if r.err != nil {
		t.Fatalf("%v\n%s", r.err, r.errOut)
	}
	if !slices.Contains(paths, "GET /signin") {
		t.Fatalf("the command's request did not reach the site: %v\n%s", paths, r.errOut)
	}
	var line *ledger.Entry
	for i, e := range r.entries {
		if strings.Contains(e.Target, "/signin") {
			line = &r.entries[i]
		}
	}
	if line == nil || line.Method != "GET" || line.Kind != "http" || line.Class != "target" || line.Collector != "role-cmd:bob" || line.Target != site.URL+"/signin?u=bob" {
		t.Fatalf("the ledger line of the command's request: %+v", line)
	}
	if r.counted() != r.rep.Requests {
		t.Errorf("the ledger counts %d requests, the summary %d", r.counted(), r.rep.Requests)
	}
	if !strings.Contains(r.notes(), "role bob: its -role-cmd ran through azhaq's loopback proxy") || !strings.Contains(r.notes(), "2 requests in 2 runs") {
		t.Errorf("the summary does not name the command and its requests: %q", r.rep.Notes)
	}
}

// A request outside the scope is answered 403 with the reason; the target
// never sees it and the role's sign-in fails with that reason, although the
// command itself exits 0. With no rule, the -url target holds its host to its port.
func TestRoleCmdRequestOutsideTheScopeIsRefusedAndFailsTheSignIn(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	a := countingSite(&hitsA, nil)
	defer a.Close()
	b := countingSite(&hitsB, nil)
	defer b.Close()
	r := runRolesCmd(t, helperCmd("get", b.URL+"/steal"), nil, "-url", a.URL+"/", "-no-paths")
	if r.err == nil {
		t.Fatalf("the sign-in went through with a refused request\n%s", r.errOut)
	}
	if hitsB.Load() != 0 {
		t.Errorf("the site outside the scope saw %d requests", hitsB.Load())
	}
	if !strings.Contains(r.errOut, "status 403") || !strings.Contains(r.errOut, "azhaq refused GET "+b.URL+"/steal") {
		t.Errorf("the command was not answered 403 with the rule:\n%s", r.errOut)
	}
	if !strings.Contains(r.notes(), "role bob: its -role-cmd made a request azhaq refused") || !strings.Contains(r.notes(), "outside the scope") {
		t.Errorf("the sign-in does not fail with the scope's reason: %q", r.rep.Notes)
	}
	for _, e := range r.entries {
		if strings.Contains(e.Target, "/steal") {
			t.Errorf("a refused request is in the ledger: %+v", e)
		}
	}
}

// HTTPS is a CONNECT: held to the scope by host and port, listed as CONNECT
// host:port under the role's name, and the bytes inside are not read.
func TestRoleCmdConnectIsInTheLedger(t *testing.T) {
	var hits atomic.Int64
	a := countingSite(&hits, nil)
	defer a.Close()
	var tlsHits atomic.Int64
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsHits.Add(1)
		fmt.Fprint(w, "inside the tunnel")
	}))
	defer secure.Close()
	var otherHits atomic.Int64
	other := countingSite(&otherHits, nil)
	defer other.Close()
	allow := []string{"-allow", "127.0.0.1:" + cmdPortOf(t, a.URL), "-allow", "127.0.0.1:" + cmdPortOf(t, secure.URL)}
	opts := append([]string{"-url", a.URL + "/", "-no-paths"}, allow...)
	r := runRolesCmd(t, helperCmd("tls", secure.URL+"/token"), nil, opts...)
	if r.err != nil {
		t.Fatalf("%v\n%s", r.err, r.errOut)
	}
	if tlsHits.Load() != 2 || !strings.Contains(r.errOut, "status 200 inside the tunnel") {
		t.Fatalf("the tunnel did not carry the request (%d hits)\n%s", tlsHits.Load(), r.errOut)
	}
	want := "127.0.0.1:" + cmdPortOf(t, secure.URL)
	var found *ledger.Entry
	for i, e := range r.entries {
		if e.Method == "CONNECT" {
			found = &r.entries[i]
		}
		if strings.Contains(e.Target, "/token") {
			t.Errorf("the ledger holds the content of the tunnel: %+v", e)
		}
	}
	if found == nil || found.Target != want || found.Kind != "http" || found.Collector != "role-cmd:bob" || found.Host != "127.0.0.1" {
		t.Fatalf("the CONNECT line: %+v, want target %s", found, want)
	}
	if r.counted() != r.rep.Requests {
		t.Errorf("the ledger counts %d requests, the summary %d", r.counted(), r.rep.Requests)
	}
	// The same host on a port the rule does not name is refused, by port.
	r = runRolesCmd(t, helperCmd("connect", "127.0.0.1:"+cmdPortOf(t, other.URL)), nil, opts...)
	if r.err == nil || !strings.Contains(r.errOut, "status line HTTP/1.1 403") || !strings.Contains(r.notes(), "CONNECT 127.0.0.1:"+cmdPortOf(t, other.URL)) {
		t.Errorf("a CONNECT to a port outside the rule: %v\n%s", r.err, r.errOut)
	}
	for _, e := range r.entries {
		if e.Method == "CONNECT" {
			t.Errorf("a refused CONNECT is in the ledger: %+v", e)
		}
	}
}

// The budget holds the command's requests: with -max-requests spent in the
// middle of the command, the next request is answered 429 with the reason, the
// sign-in fails with it, and the run stops on its limit.
func TestRoleCmdBudgetRefusesTheNextRequest(t *testing.T) {
	var hits atomic.Int64
	var paths []string
	site := countingSite(&hits, &paths)
	defer site.Close()
	// alice signs in first, with the whole budget before her.
	r := runRolesArgs(t, []string{"-role-cmd", "alice=" + helperCmd("get", site.URL+"/one", site.URL+"/two", site.URL+"/three"), "-role-cmd", "bob=echo tok"},
		"-url", site.URL+"/", "-no-paths", "-max-requests", "2")
	if r.err == nil || exitCode(r.err) != exitLimit {
		t.Fatalf("exit %d (%v), want the limit's\n%s", exitCode(r.err), r.err, r.errOut)
	}
	if !slices.Equal(paths, []string{"GET /one", "GET /two"}) {
		t.Errorf("the site saw %v, want the two the budget allows", paths)
	}
	if !strings.Contains(r.errOut, "/three status 429") || !strings.Contains(r.errOut, "the request budget is spent") {
		t.Errorf("the third request was not answered 429 with the reason:\n%s", r.errOut)
	}
	if !strings.Contains(r.notes(), "role alice: its -role-cmd made a request azhaq refused") || !strings.Contains(r.notes(), "the request budget is spent") {
		t.Errorf("the run does not say the budget refused the sign-in: %q", r.rep.Notes)
	}
	if r.rep.Requests != 2 || r.counted() != 2 {
		t.Errorf("requests %d, ledger %d, want 2", r.rep.Requests, r.counted())
	}
}

// -role-cmd-direct runs the command with no proxy, as before: its request to
// a site outside the scope goes out, is neither held nor listed, and the
// summary says so.
func TestRoleCmdDirectKeepsTheOldBehaviour(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	var paths []string
	a := countingSite(&hitsA, nil)
	defer a.Close()
	b := countingSite(&hitsB, &paths)
	defer b.Close()
	cmd := helperCmd("direct", b.URL+"/cmdping")
	r := runRolesCmd(t, cmd, []string{"-role-cmd-direct"}, "-url", a.URL+"/", "-no-paths")
	if r.err != nil {
		t.Fatalf("%v\n%s", r.err, r.errOut)
	}
	if !slices.Contains(paths, "GET /cmdping") {
		t.Fatalf("the command's request did not go out: %v", paths)
	}
	for _, e := range r.entries {
		if strings.Contains(e.Target, "/cmdping") || e.Collector == "role-cmd:bob" {
			t.Errorf("the ledger lists the command's own request: %+v", e)
		}
	}
	if r.counted() != r.rep.Requests {
		t.Errorf("the ledger counts %d requests, the summary %d", r.counted(), r.rep.Requests)
	}
	if !strings.Contains(r.notes(), "its -role-cmd ran with -role-cmd-direct, with no proxy") {
		t.Errorf("the summary does not say the command ran with no proxy: %q", r.rep.Notes)
	}
}

// A command that sends without the proxy variables (a raw socket, a tool that
// ignores them) is outside the ledger and the scope, with the proxy on.
func TestRoleCmdThatIgnoresTheProxyIsOutsideTheLedger(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	var paths []string
	a := countingSite(&hitsA, nil)
	defer a.Close()
	b := countingSite(&hitsB, &paths)
	defer b.Close()
	r := runRolesCmd(t, helperCmd("direct", b.URL+"/ignored"), nil, "-url", a.URL+"/", "-no-paths")
	if r.err != nil || !slices.Contains(paths, "GET /ignored") {
		t.Fatalf("the command's request did not go out: %v %v", r.err, paths)
	}
	for _, e := range r.entries {
		if strings.Contains(e.Target, "/ignored") {
			t.Errorf("the ledger lists a request that skipped the proxy: %+v", e)
		}
	}
	if !strings.Contains(r.notes(), "a request it makes without honouring the proxy variables is outside the ledger") {
		t.Errorf("the summary does not say what the proxy cannot see: %q", r.rep.Notes)
	}
}

// plan names the role commands that would run through the proxy, or with none.
func TestPlanNamesTheRoleCommandsAndTheirProxy(t *testing.T) {
	for _, tc := range []struct {
		pre  []string
		want string
	}{
		{nil, "role bob: its -role-cmd would run through azhaq's loopback proxy"},
		{[]string{"-role-cmd-direct"}, "role bob: its -role-cmd would run with -role-cmd-direct, with no proxy"},
	} {
		out, errOut, err := captureBoth(t, func() error {
			return cmdRoles(append(append([]string{"-plan", "-role", "anon", "-role-cmd", "bob=echo tok"}, tc.pre...), "--", "-url", "http://127.0.0.1:1/"))
		})
		if err != nil || !strings.Contains(out, tc.want) {
			t.Errorf("plan %v: %v\n%s\n%s", tc.pre, err, out, errOut)
		}
		o2, _, _ := captureBoth(t, func() error {
			return cmdRoles(append(append([]string{"-plan", "-json", "-role", "anon", "-role-cmd", "bob=echo tok"}, tc.pre...), "--", "-url", "http://127.0.0.1:1/"))
		})
		var p struct {
			RoleCmds []string `json:"role_cmds"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(o2)), &p) != nil || len(p.RoleCmds) != 1 || !strings.Contains(p.RoleCmds[0], tc.want) {
			t.Errorf("plan -json %v: %s", tc.pre, o2)
		}
	}
}
