package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mcpOnRealAzhaq is a server whose tools run this test binary as azhaq, held
// to the loopback site and to held.
func mcpOnRealAzhaq(t *testing.T, site *httptest.Server, held heldRun) *mcpServer {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if held.Sources == "" {
		held.Sources = "none"
	}
	s := &mcpServer{exe: exe, dir: filepath.Join(dir, "ws"), lock: []string{"-allow", "127.0.0.1:" + srvPort(t, site)}, locked: true, held: held}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return s
}

// A server started with -proxy sends what its tools send to a loopback
// target through the proxy, as the environment's proxy variables never do.
func TestMCPProxyCarriesToolRequestsToALoopbackTarget(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>home</title><a href="/about">about</a></html>`)
	}))
	defer site.Close()
	stub, seen := countingProxy(site, false, 0)
	defer stub.Close()
	// The environment's proxy must not be what carries it.
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	s := mcpOnRealAzhaq(t, site, heldRun{Proxy: stub.URL})
	target := site.URL + "/"
	for tool, args := range map[string]map[string]any{
		"azhaq_probe": {"targets": []any{target}},
		"azhaq_map":   {"url": target, "workspace": "w"},
	} {
		before := len(seen())
		text, isErr := callText(t, s, tool, args)
		if isErr {
			t.Fatalf("%s: %s", tool, text)
		}
		if after := len(seen()); after <= before {
			t.Errorf("%s: the proxy stub saw no request of the call (%d before, %d after): %s", tool, before, after, text)
		}
	}
	got := strings.Join(seen(), "\n")
	if !strings.Contains(got, "GET /") {
		t.Errorf("the proxy stub recorded %q, want GET /", got)
	}
}

// The held -proxy and -chrome-proxy reach each command under the flag that
// command has for them, and a proxy that carries no TCP or DNS is not given
// to the commands that send those.
func TestMCPProxyOptionsPerCommand(t *testing.T) {
	h := heldRun{Proxy: "http://u:secret@127.0.0.1:8080", ChromeProxy: "socks5://127.0.0.1:9050", Sources: "crtsh"}
	for cmd, want := range map[string]string{
		"run":    "-proxy http://u:secret@127.0.0.1:8080 -source-proxy http://u:secret@127.0.0.1:8080 -chrome-proxy socks5://127.0.0.1:9050",
		"plan":   "-proxy http://u:secret@127.0.0.1:8080 -source-proxy http://u:secret@127.0.0.1:8080 -chrome-proxy socks5://127.0.0.1:9050",
		"resume": "-proxy http://u:secret@127.0.0.1:8080 -source-proxy http://u:secret@127.0.0.1:8080 -chrome-proxy socks5://127.0.0.1:9050",
		"probe":  "-proxy http://u:secret@127.0.0.1:8080",
		"dirs":   "-proxy http://u:secret@127.0.0.1:8080",
		"params": "-proxy http://u:secret@127.0.0.1:8080",
		"roles":  "-proxy http://u:secret@127.0.0.1:8080",
		"subs":   "-proxy http://u:secret@127.0.0.1:8080 -http-proxy http://u:secret@127.0.0.1:8080",
		"ports":  "",
		"dns":    "",
	} {
		got := strings.Join(h.proxyOptions(cmd), " ")
		if got != want {
			t.Errorf("%s gets %q, want %q", cmd, got, want)
		}
	}
	for _, cmd := range []string{"ports", "dns"} {
		if err := h.proxyRefusal(cmd); err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s through an http proxy: %v", cmd, err)
		}
	}
	for _, cmd := range []string{"run", "probe", "subs"} {
		if err := h.proxyRefusal(cmd); err != nil {
			t.Errorf("%s refused: %v", cmd, err)
		}
	}
	h.Proxy = "socks5://u:pw@127.0.0.1:1080"
	if got := strings.Join(h.proxyOptions("ports"), " "); got != "-proxy 127.0.0.1:1080 -proxy-auth u:pw" {
		t.Errorf("ports gets %q", got)
	}
	if got := strings.Join(h.proxyOptions("dns"), " "); got != "-proxy socks5://u:pw@127.0.0.1:1080" {
		t.Errorf("dns gets %q", got)
	}
	if got := strings.Join(h.proxyOptions("run"), " "); !strings.Contains(got, "-port-proxy 127.0.0.1:1080 -port-proxy-auth u:pw") {
		t.Errorf("run gets %q", got)
	}
	if err := h.proxyRefusal("ports"); err != nil {
		t.Errorf("ports through socks5: %v", err)
	}
}

// azhaq_status and azhaq_scope show the proxy, without its password; a tool
// call cannot set one.
func TestMCPStatusShowsTheProxy(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true,
		held: heldRun{Proxy: "http://u:secret@127.0.0.1:8080"}}
	for _, tool := range []string{"azhaq_status", "azhaq_scope"} {
		text, isErr := callText(t, s, tool, nil)
		if isErr || !strings.Contains(text, `"proxy"`) || !strings.Contains(text, "http://127.0.0.1:8080") || strings.Contains(text, "secret") {
			t.Errorf("%s: %v %s", tool, isErr, text)
		}
	}
	if err := checkArgs("azhaq_probe", map[string]any{"targets": []any{"http://127.0.0.1/"}, "proxy": "http://x"}); err == nil {
		t.Error("a call sets the proxy: it must be the server's alone")
	}
	s.held = heldRun{}
	text, _ := callText(t, s, "azhaq_status", nil)
	if !strings.Contains(text, "requests go direct") {
		t.Errorf("no proxy: %s", text)
	}
	// The call that cannot go through it says so and sends nothing.
	s.held = heldRun{Proxy: "http://127.0.0.1:8080"}
	if text, isErr := callText(t, s, "azhaq_ports", map[string]any{"hosts": []any{"127.0.0.1"}}); !isErr || !strings.Contains(text, "not a socks5 proxy") {
		t.Errorf("azhaq_ports through an http proxy: %v %s", isErr, text)
	}
	if _, err := os.Stat(filepath.Join(dir, "args")); err == nil {
		t.Error("a refused call ran a command")
	}
}

// -proxy is refused at start when no run would take it, with run's wording;
// the egress flags of run are on mcp.
func TestMCPTakesTheProxyFlagsOfRun(t *testing.T) {
	if _, errOut, code := cli(t, "mcp", "-allow", "127.0.0.1", "-proxy", "ftp://x:1", "-dir", t.TempDir()); code != exitUsage || !strings.Contains(errOut, "-proxy wants http://host:port, https://host:port or socks5://host:port") {
		t.Errorf("a bad -proxy: exit %d: %s", code, errOut)
	}
	if _, errOut, code := cli(t, "mcp", "-allow", "127.0.0.1", "-chrome-proxy", "nonsense", "-dir", t.TempDir()); code != exitUsage || !strings.Contains(errOut, "-chrome-proxy wants a URL") {
		t.Errorf("a bad -chrome-proxy: exit %d: %s", code, errOut)
	}
	run, mcp := flagsOf("run"), flagsOf("mcp")
	for _, f := range []string{"proxy", "chrome-proxy"} {
		if run.Lookup(f) == nil || mcp.Lookup(f) == nil {
			t.Errorf("-%s is not on both run and mcp", f)
		}
	}
}
