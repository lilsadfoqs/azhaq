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
