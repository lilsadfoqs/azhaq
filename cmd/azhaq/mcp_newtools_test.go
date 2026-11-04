package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// realMCPServer is a server that runs the test binary as azhaq, in a
// directory of its own, held to lock.
func realMCPServer(t *testing.T, lock []string, held heldRun, budget int64) *mcpServer {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &mcpServer{exe: exe, dir: filepath.Join(dir, "ws"), lock: lock, locked: len(lock) > 0, budget: budget, held: held}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return s
}

// wireApp records every request it gets: method, path and body.
type wireApp struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []string
}

func newWireApp(t *testing.T) *wireApp {
	t.Helper()
	app := &wireApp{}
	app.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		app.mu.Lock()
		app.hits = append(app.hits, r.Method+" "+r.URL.RequestURI())
		app.mu.Unlock()
		switch {
		case r.URL.Path == "/open":
			fmt.Fprint(w, "an open path with its own answer, longer than the rest")
		case r.URL.Path == "/page":
			w.Header().Set("Content-Type", "text/html")
			if r.URL.Query().Has("debug") {
				fmt.Fprint(w, "<title>page</title>debug is on and the page is quite different in size and words")
			} else {
				fmt.Fprint(w, "<title>page</title>plain")
			}
		case r.URL.Path == "/createdb":
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(app.srv.Close)
	return app
}

func (app *wireApp) asked() []string {
	app.mu.Lock()
	defer app.mu.Unlock()
	return append([]string(nil), app.hits...)
}

func (app *wireApp) count(prefix string) int {
	n := 0
	for _, h := range app.asked() {
		if strings.HasPrefix(h, prefix) {
			n++
		}
	}
	return n
}

// ledgerTargets counts the lines to targets in a ledger and checks its chain.
func ledgerTargets(t *testing.T, path string) (int64, int) {
	t.Helper()
	var lines int64
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Counted() {
			lines++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c, err := ledger.Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	return lines, c.Seals
}

func toolSummary(t *testing.T, text string) map[string]any {
	t.Helper()
	var got struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	return got.Summary
}

// The new tools are listed with truthful annotations and bounded
// schemas: an unbounded word list is refused by the schema check.
func TestMCPNewToolsListedBoundedAndAnnotated(t *testing.T) {
	byName := map[string]map[string]any{}
	for _, tool := range mcpTools() {
		byName[tool["name"].(string)] = tool
	}
	for _, name := range []string{"azhaq_dirs", "azhaq_params", "azhaq_dns_brute", "azhaq_roles_writes"} {
		if byName[name] == nil {
			t.Errorf("no tool %s", name)
		}
	}
	ann := func(name string) map[string]any { a, _ := byName[name]["annotations"].(map[string]any); return a }
	if ann("azhaq_dirs")["readOnlyHint"] != false || ann("azhaq_params")["readOnlyHint"] != false {
		t.Errorf("dirs and params send requests to targets and must not claim read-only: %v %v", ann("azhaq_dirs"), ann("azhaq_params"))
	}
	if ann("azhaq_params")["destructiveHint"] != true || ann("azhaq_roles_writes")["destructiveHint"] != true {
		t.Errorf("the tools that can send writes must say so: %v %v", ann("azhaq_params"), ann("azhaq_roles_writes"))
	}
	if ann("azhaq_dns_brute")["readOnlyHint"] != true {
		t.Errorf("dns brute sends only resolver queries: %v", ann("azhaq_dns_brute"))
	}
	if _, ok := byName["azhaq_ports"]["inputSchema"].(map[string]any)["properties"].(map[string]any)["udp_ports"]; !ok {
		t.Error("azhaq_ports takes no udp_ports")
	}
	words := make([]any, 5001)
	for i := range words {
		words[i] = "w"
	}
	if err := checkArgs("azhaq_dirs", map[string]any{"targets": []any{"http://127.0.0.1/"}, "words": words}); err == nil || !strings.Contains(err.Error(), "at most 5000") {
		t.Errorf("an unbounded word list passed the schema: %v", err)
	}
	if err := checkArgs("azhaq_dns_brute", map[string]any{"domain": []any{"lab.test"}}); err == nil {
		t.Error("dns brute without words passed: its guesses would be unbounded")
	}
	// The locked-down defaults: no third-party sources, no history, no writes.
	s := &mcpServer{dir: t.TempDir()}
	text, _ := callText(t, s, "azhaq_scope", nil)
	var scope struct {
		Options map[string]any `json:"run_options"`
	}
	if err := json.Unmarshal([]byte(text), &scope); err != nil || scope.Options["sources"] != "none" || scope.Options["history"] != false || scope.Options["allow_writes"] != false {
		t.Errorf("the default run options are not locked down: %v %s", err, text)
	}
	if got := strings.Join(s.held.options("run"), " "); !strings.Contains(got, "-sources none") || !strings.Contains(got, "-no-history") {
		t.Errorf("a map call does not inherit the defaults: %s", got)
	}
}

// Each new tool under the server's lock, budget and deny rules, with a
// complete ledger: the summary's requests are the ledger's lines to
// targets and the requests the target was asked.
func TestMCPNewToolsUnderLockBudgetAndLedger(t *testing.T) {
	app := newWireApp(t)
	s := realMCPServer(t, []string{"-allow", "127.0.0.1", "-allow", "lab.test", "-deny-path", `^/secret$`}, heldRun{}, 100000)

	// dirs: the word the deny rule matches is never asked.
	text, isErr := callText(t, s, "azhaq_dirs", map[string]any{"targets": []any{app.srv.URL + "/"}, "words": []any{"open", "secret"}})
	if isErr {
		t.Fatalf("azhaq_dirs: %s", text)
	}
	sum := toolSummary(t, text)
	if !strings.Contains(text, app.srv.URL+"/open") {
		t.Errorf("the found path is not in the rows: %s", text)
	}
	if app.count("GET /secret") != 0 {
		t.Errorf("the denied path was asked: %v", app.asked())
	}
	lines, seals := ledgerTargets(t, s.serverLedger())
	if req := int64(sum["requests"].(float64)); lines != req || req != int64(len(app.asked())) || seals != 1 {
		t.Errorf("dirs: ledger %d lines (%d seals), summary %v requests, target asked %d", lines, seals, sum["requests"], len(app.asked()))
	}

	// params by GET: names in the query, no body method without the opt-in.
	before := len(app.asked())
	text, isErr = callText(t, s, "azhaq_params", map[string]any{"targets": []any{app.srv.URL + "/page"}, "words": []any{"debug", "q"}})
	if isErr {
		t.Fatalf("azhaq_params: %s", text)
	}
	sum = toolSummary(t, text)
	lines, seals = ledgerTargets(t, s.serverLedger())
	// Ledger completeness: every request the target was asked, by both
	// calls so far, is a line to a target in the ledger.
	if lines != int64(len(app.asked())) || seals != 2 || sum["requests"].(float64) == 0 {
		t.Errorf("params: ledger %d lines (%d seals), summary %v, target asked %d in all", lines, seals, sum["requests"], len(app.asked()))
	}
	if len(app.asked()) == before {
		t.Error("params asked nothing")
	}
	if text, isErr := callText(t, s, "azhaq_params", map[string]any{"targets": []any{app.srv.URL + "/page"}, "method": "POST"}); !isErr || !strings.Contains(text, "-allow-writes") {
		t.Errorf("a body method without the server's write opt-in: %v %s", isErr, text)
	}
	if n := len(app.asked()); n != before && app.count("POST ") != 0 {
		t.Errorf("a write was sent without the opt-in: %v", app.asked())
	}

	// DNS brute force: guesses go to the held resolver, not the targets.
	var asked atomic.Int64
	zone := serveCountingZone(t, &asked, map[string]string{"app.lab.test": "127.0.0.1"})
	s.held.Resolvers = zone
	hitsBefore := len(app.asked())
	text, isErr = callText(t, s, "azhaq_dns_brute", map[string]any{"domain": []any{"lab.test"}, "words": []any{"app", "nope"}})
	if isErr {
		t.Fatalf("azhaq_dns_brute: %s", text)
	}
	if !strings.Contains(text, "app.lab.test") || asked.Load() == 0 {
		t.Errorf("the guessed name that resolves is not in the rows, or the resolver was never asked: %s (asked %d)", text, asked.Load())
	}
	if len(app.asked()) != hitsBefore {
		t.Errorf("dns brute sent requests to a target: %v", app.asked())
	}
	if _, seals := ledgerTargets(t, s.serverLedger()); seals != 3 {
		t.Errorf("the server's ledger has %d seals, want one per stateless call (3)", seals)
	}
	sum = toolSummary(t, text)
	if dq, _ := sum["dns_queries"].(float64); dq == 0 {
		t.Errorf("the dns summary counts no queries: %v", sum)
	}

	// Role write replay without the opt-in is refused before anything
	// is sent; a dry run sends no write.
	roles := []any{map[string]any{"name": "anon"}, map[string]any{"name": "user", "header": []any{"Authorization: Bearer x"}}}
	hitsBefore = len(app.asked())
	if text, isErr := callText(t, s, "azhaq_roles_writes", map[string]any{"url": app.srv.URL + "/", "roles": roles, "replay_writes": "put"}); !isErr || !strings.Contains(text, "-allow-writes") {
		t.Errorf("write replay without the opt-in: %v %s", isErr, text)
	}
	if len(app.asked()) != hitsBefore {
		t.Errorf("the refused replay sent requests: %v", app.asked()[hitsBefore:])
	}
	if text, isErr := callText(t, s, "azhaq_roles_writes", map[string]any{"url": app.srv.URL + "/", "roles": roles, "replay_writes": "put", "dry_writes": true, "workspace": "writes"}); isErr {
		t.Errorf("a dry write replay: %s", text)
	}
	if app.count("PUT ") != 0 || app.count("POST ") != 0 || app.count("DELETE ") != 0 {
		t.Errorf("the dry replay sent a write: %v", app.asked())
	}
}

// UDP ports over MCP: a UDP service that answers is listed open.
func TestMCPUDPPorts(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = pc.WriteTo([]byte("hello\n"), addr)
			}
		}
	}()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	s := realMCPServer(t, []string{"-allow", "127.0.0.1"}, heldRun{}, 100000)
	text, isErr := callText(t, s, "azhaq_ports", map[string]any{"hosts": []any{"127.0.0.1"}, "udp_ports": port})
	if isErr {
		t.Fatalf("azhaq_ports with udp_ports: %s", text)
	}
	if !strings.Contains(text, port) || !strings.Contains(text, "udp") {
		t.Errorf("the UDP port is not in the rows: %s", text)
	}
	if _, err := os.Stat(s.serverLedger()); err != nil {
		t.Errorf("the call wrote no server ledger: %v", err)
	}
}

// A spent budget and a target outside the scope refuse every new tool
// before any network activity.
func TestMCPNewToolsRefuseSpentBudgetAndOutsideScope(t *testing.T) {
	app := newWireApp(t)
	roles := []any{map[string]any{"name": "anon"}, map[string]any{"name": "user", "header": []any{"Authorization: Bearer x"}}}
	calls := map[string]map[string]any{
		"azhaq_dirs":         {"targets": []any{app.srv.URL + "/"}},
		"azhaq_params":       {"targets": []any{app.srv.URL + "/page"}},
		"azhaq_dns_brute":    {"domain": []any{"lab.test"}, "words": []any{"app"}},
		"azhaq_roles_writes": {"url": app.srv.URL + "/", "roles": roles, "replay_writes": "put", "dry_writes": true},
	}
	spent := realMCPServer(t, []string{"-allow", "127.0.0.1", "-allow", "lab.test"}, heldRun{}, 10)
	spent.used = 10
	for tool, args := range calls {
		if text, isErr := callText(t, spent, tool, args); !isErr || !strings.Contains(text, "budget") {
			t.Errorf("%s with a spent budget: %v %s", tool, isErr, text)
		}
	}
	if got := app.asked(); len(got) != 0 {
		t.Errorf("a spent budget sent %v", got)
	}

	outside := realMCPServer(t, []string{"-allow", "example.com"}, heldRun{}, 100000)
	for tool, args := range calls {
		if tool == "azhaq_roles_writes" {
			continue // held by the lock of its runs, as azhaq_roles is
		}
		if text, isErr := callText(t, outside, tool, args); !isErr || !strings.Contains(text, "outside the scope") {
			t.Errorf("%s outside the scope: %v %s", tool, isErr, text)
		}
	}
	if got := app.asked(); len(got) != 0 {
		t.Errorf("an outside-scope call sent %v", got)
	}
}

// Plan and wire agree on the state-changing GET: the plan names it and
// sends nothing; the map then sends that very request.
func TestMCPPlanAndWireAgreeOnStateChangingGET(t *testing.T) {
	app := newWireApp(t)
	s := realMCPServer(t, []string{"-allow", "127.0.0.1"}, heldRun{}, 100000)
	text, isErr := callText(t, s, "azhaq_plan", map[string]any{"targets": []any{app.srv.URL + "/createdb"}, "depth": float64(0)})
	if isErr {
		t.Fatalf("azhaq_plan: %s", text)
	}
	var planned struct {
		Plan []struct {
			StateChanging []stateChangeEntry `json:"state_changing"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(text), &planned); err != nil || len(planned.Plan) != 1 || len(planned.Plan[0].StateChanging) != 1 {
		t.Fatalf("the plan names no state-changing GET: %v %s", err, text)
	}
	if e := planned.Plan[0].StateChanging[0]; e.URL != app.srv.URL+"/createdb" || e.DenyPath != "-deny-path ^/createdb$" {
		t.Errorf("planned %+v", e)
	}
	if got := app.asked(); len(got) != 0 {
		t.Fatalf("the plan sent %v", got)
	}
	text, isErr = callText(t, s, "azhaq_map", map[string]any{"url": app.srv.URL + "/createdb", "workspace": "eq", "depth": float64(0)})
	if isErr {
		t.Fatalf("azhaq_map: %s", text)
	}
	if n := app.count("GET /createdb"); n == 0 {
		t.Errorf("the map never sent the GET the plan named: %v", app.asked())
	}
	if sum := toolSummary(t, text); !strings.Contains(text, `"state_changing"`) || sum["requests"] == nil {
		t.Errorf("the map's summary does not name it: %s", text)
	}
	if !slices.Contains(app.asked(), "GET /createdb") {
		t.Errorf("asked %v", app.asked())
	}
}
