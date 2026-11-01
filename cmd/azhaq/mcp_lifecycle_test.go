package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const mcpInitialize = `{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`

// The lifecycle: before initialize only ping is answered, a second
// initialize is refused, and what is sent back to back is answered in the
// order it was sent. The scope and the budget hold throughout.
func TestMCPLifecycle(t *testing.T) {
	s := &mcpServer{dir: t.TempDir(), lock: []string{"-allow", "127.0.0.1:3001"}, locked: true, budget: 10}
	var out strings.Builder
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"azhaq_scope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":11,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
		strings.Replace(mcpInitialize, "%d", "2", 1),
		strings.Replace(mcpInitialize, "%d", "3", 1),
		`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":5,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":6,"method":"nope"}`,
	}, "\n") + "\n"
	if err := s.serve(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	type reply struct {
		ID     float64 `json:"id"`
		Error  *rpcError
		Result map[string]any
	}
	var got []reply
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r reply
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		got = append(got, r)
	}
	want := []struct {
		id      float64
		errPart string // "" for a result
	}{{1, "not initialized"}, {10, "not initialized"}, {11, ""}, {2, ""}, {3, "already initialized"}, {4, ""}, {5, ""}, {6, "method not found"}}
	if len(got) != len(want) {
		t.Fatalf("%d responses, want %d: %s", len(got), len(want), out.String())
	}
	for i, w := range want {
		g := got[i]
		switch {
		case g.ID != w.id:
			t.Errorf("response %d is for id %v, want %v (answers out of order)", i, g.ID, w.id)
		case w.errPart == "" && g.Error != nil:
			t.Errorf("id %v: %v", w.id, g.Error.Message)
		case w.errPart != "" && (g.Error == nil || !strings.Contains(g.Error.Message, w.errPart)):
			t.Errorf("id %v: want an error with %q, got %+v", w.id, w.errPart, g)
		}
	}
	if got[3].Result["protocolVersion"] != "2025-06-18" {
		t.Errorf("initialize result %v", got[3].Result)
	}
}

// After initialize a tool call still holds the scope: a target outside it is
// refused, not asked.
func TestMCPScopeHoldsAfterInitialize(t *testing.T) {
	s := &mcpServer{dir: t.TempDir(), exe: "/nonexistent", lock: []string{"-allow", "127.0.0.1:3001"}, locked: true, budget: 10}
	got := rpcAll(t, s,
		strings.Replace(mcpInitialize, "%d", "1", 1),
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"azhaq_subdomains","arguments":{"domain":"outside.test"}}}`)
	res, _ := got[2]["result"].(map[string]any)
	text, _ := json.Marshal(res)
	if res["isError"] != true || !strings.Contains(string(text), "outside the scope") {
		t.Errorf("%s", text)
	}
}
