package contract

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
