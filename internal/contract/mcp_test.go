package contract

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mcpClient is a client of azhaq mcp over stdio.
type mcpClient struct {
	t    *testing.T
	cmd  *exec.Cmd
	in   io.WriteCloser
	sc   *bufio.Scanner
	next int
}

func startMCP(t *testing.T, dir string, args ...string) *mcpClient {
	t.Helper()
	cmd := exec.Command(binPath, append([]string{"mcp", "-dir", filepath.Join(dir, "ws")}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "AZHAQ_DATA_DIR=" + filepath.Join(dir, "data")}
	in, err := cmd.StdinPipe()
	must(t, err)
	out, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	c := &mcpClient{t: t, cmd: cmd, in: in, sc: bufio.NewScanner(out)}
	c.sc.Buffer(make([]byte, 1<<20), 1<<26)
	t.Cleanup(func() {
		_ = in.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "contract", "version": "1"}})
	_, _ = fmt.Fprintln(in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return c
}

func (c *mcpClient) call(method string, params any) json.RawMessage {
	c.t.Helper()
	c.next++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method, "params": params})
	_, _ = fmt.Fprintln(c.in, string(b))
	if !c.sc.Scan() {
		c.t.Fatalf("mcp: no answer to %s: %v", method, c.sc.Err())
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string }
	}
	must(c.t, json.Unmarshal(c.sc.Bytes(), &resp))
	if resp.Error != nil {
		c.t.Fatalf("mcp %s: %s", method, resp.Error.Message)
	}
	return resp.Result
}

// Tool calls a tool and returns the summary of its answer.
func (c *mcpClient) Tool(name string, args map[string]any) Summary {
	c.t.Helper()
	raw := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	var res struct {
		Content []struct{ Text string }
		IsError bool
	}
	must(c.t, json.Unmarshal(raw, &res))
	if res.IsError || len(res.Content) == 0 {
		c.t.Fatalf("mcp %s failed: %s", name, raw)
	}
	var body struct{ Summary Summary }
	must(c.t, json.Unmarshal([]byte(res.Content[0].Text), &body))
	return body.Summary
}

// Refused is what the server says to a call it refuses, in the protocol's error or in the tool's.
func (c *mcpClient) Refused(name string, args map[string]any) string {
	c.t.Helper()
	c.next++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.next, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	_, _ = fmt.Fprintln(c.in, string(b))
	if !c.sc.Scan() {
		c.t.Fatalf("mcp: no answer to %s: %v", name, c.sc.Err())
	}
	var resp struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
		Error *struct{ Message string }
	}
	must(c.t, json.Unmarshal(c.sc.Bytes(), &resp))
	switch {
	case resp.Error != nil:
		return resp.Error.Message
	case resp.Result.IsError && len(resp.Result.Content) > 0:
		return resp.Result.Content[0].Text
	}
	c.t.Errorf("mcp %s was not refused: %s", name, c.sc.Text())
	return ""
}

// What the server was started with holds for every call: the -deny-path
// rules keep a URL out, and no argument of a call adds a rule, a scope or a
// budget.
func TestMCPHoldsWhatItWasStartedWith(t *testing.T) {
	l := newLabs(t)
	c := startMCP(t, l.Dir, "-allow", l.Allow(), "-deny-path", "^/about", "-max-requests", "200")
	c.Tool("azhaq_map", map[string]any{"url": l.Site.URL, "workspace": "w"})
	if l.Site.Wire.Total() == 0 {
		t.Fatal("the map sent nothing")
	}
	for k := range l.Site.Wire.HTTP() {
		if strings.Contains(k, "/about") {
			t.Errorf("the server was started with -deny-path ^/about and a map sent %s", k)
		}
	}
	// The control: the same map without the rule asks /about, so its absence above is the rule's doing.
	open := newLabs(t)
	startMCP(t, open.Dir, "-allow", open.Allow()).Tool("azhaq_map", map[string]any{"url": open.Site.URL, "workspace": "w"})
	if _, ok := open.Site.Wire.HTTP()[canon("GET", open.Site.URL+"/about")]; !ok {
		t.Error("a map with no -deny-path never asks /about, so the check above proves nothing")
	}
	before := l.Site.Wire.Total()
	for _, extra := range []map[string]any{
		{"deny_path": []string{"^/x"}},
		{"deny-path": "^/x"},
		{"allow": []string{"example.com"}},
		{"max_requests": 100000},
		{"rate": 1000},
	} {
		args := map[string]any{"url": l.Site.URL + "/products"}
		for k, v := range extra {
			args[k] = v
		}
		if msg := c.Refused("azhaq_map", args); msg == "" {
			t.Errorf("%v: no reason given", extra)
		}
	}
	if got := l.Site.Wire.Total(); got != before {
		t.Errorf("refused calls sent %d requests", got-before)
	}
}

// A server started with -unlocked refuses port scans, and no tool scans UDP
// or sends a write, a wordlist or a DNS brute force: they have no argument
// for it.
func TestMCPUnlockedRefusesPortScansAndNoToolTakesWhatItLeavesOut(t *testing.T) {
	l := newLabs(t)
	l.Ports = newPortLab(t)
	c := startMCP(t, l.Dir, "-unlocked")
	if msg := c.Refused("azhaq_ports", map[string]any{"hosts": []string{"127.0.0.1"}, "ports": portOf(l.Ports.Banner)}); !strings.Contains(msg, "unlocked") && !strings.Contains(msg, "scope") {
		t.Errorf("the port scan was refused, but not for the scope: %q", msg)
	}
	if n := l.Ports.Wire.Total(); n != 0 {
		t.Errorf("%d connections reached the port after the refusal", n)
	}
	scoped := startMCP(t, l.Dir, "-allow", "127.0.0.1")
	for tool, args := range map[string]map[string]any{
		"azhaq_ports": {"hosts": []string{"127.0.0.1"}, "ports": portOf(l.Ports.Banner), "udp": "53"},
		"azhaq_map":   {"url": l.Site.URL, "replay_writes": "post"},
		"azhaq_probe": {"targets": []string{l.Site.URL}, "method": "POST"},
	} {
		if msg := scoped.Refused(tool, args); !strings.Contains(msg, "argument") {
			t.Errorf("%s with an argument it does not take: %q", tool, msg)
		}
	}
	if n := l.Ports.Wire.Total() + l.Site.Wire.Total(); n != 0 {
		t.Errorf("%d requests were sent by calls that were refused", n)
	}
}

// No tool that sends takes an argument for what the page leaves out of the
// tools: UDP, a write or a body of the client's, a wordlist, DNS brute force.
func TestNoMCPToolThatSendsTakesWhatTheToolsLeaveOut(t *testing.T) {
	l := newLabs(t)
	c := startMCP(t, l.Dir, "-allow", l.Allow())
	var list struct {
		Tools []struct {
			Name        string
			InputSchema struct {
				Properties map[string]any `json:"properties"`
			} `json:"inputSchema"`
		}
	}
	must(t, json.Unmarshal(c.call("tools/list", map[string]any{}), &list))
	sends := map[string]bool{"azhaq_plan": true, "azhaq_map": true, "azhaq_resume": true, "azhaq_subdomains": true, "azhaq_probe": true, "azhaq_ports": true, "azhaq_roles": true}
	seen := 0
	for _, tool := range list.Tools {
		if !sends[tool.Name] {
			continue
		}
		seen++
		for name := range tool.InputSchema.Properties {
			for _, left := range []string{"udp", "write", "method", "body", "data", "wordlist", "words", "dirs", "params", "brute", "permut", "fuzz"} {
				if strings.Contains(strings.ToLower(name), left) {
					t.Errorf("%s takes %q, which the page says the tools leave out", tool.Name, name)
				}
			}
		}
	}
	if seen != len(sends) {
		t.Errorf("%d of the %d tools that send were listed", seen, len(sends))
	}
}

// A kill file in the server's -dir stops a call that uses the workspace, which
// sends nothing and says so; the list of targets the call was given stays
// while the run can be resumed, and azhaq_resume goes on once the file is
// removed, after which the list is gone.
func TestMCPKillFileStopsTheWorkspaceAndResumeGoesOn(t *testing.T) {
	l := newLabs(t)
	c := startMCP(t, l.Dir, "-allow", l.Allow())
	ws := filepath.Join(l.Dir, "ws")
	lists := func() []string { m, _ := filepath.Glob(filepath.Join(ws, ".targets-*")); return m }
	must(t, os.MkdirAll(ws, 0o755))
	stop := filepath.Join(ws, "w.db.stop")
	must(t, os.WriteFile(stop, nil, 0o644))
	s := c.Tool("azhaq_map", map[string]any{"targets": []string{l.Site.URL}, "workspace": "w"})
	if !strings.Contains(s.Stopped, "the kill switch") || s.Requests != 0 || l.Site.Wire.Total() != 0 {
		t.Errorf("stopped %q, %d requests, %d reached the site", s.Stopped, s.Requests, l.Site.Wire.Total())
	}
	if len(lists()) == 0 {
		t.Error("the list of targets of a run that can be resumed is gone")
	}
	must(t, os.Remove(stop))
	s = c.Tool("azhaq_resume", map[string]any{"workspace": "w"})
	if s.Stopped != "" || s.Requests == 0 {
		t.Errorf("resume after removing the file: stopped %q, %d requests", s.Stopped, s.Requests)
	}
	if got := lists(); len(got) != 0 {
		t.Errorf("the run is complete and its list of targets is still there: %v", got)
	}
}
