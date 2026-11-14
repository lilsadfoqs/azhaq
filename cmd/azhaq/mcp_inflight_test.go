package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A status call sent with a map, before the map answers, says what is
// reserved: used counts the calls that ended, and in_flight lists the call
// running with the -max-requests it was handed. A call waiting for the
// sending slot is not in it. When the map ends its requests move from
// in_flight to used.
func TestMCPStatusListsTheCallsInFlight(t *testing.T) {
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 20, started: true}
	t.Setenv("FAKE_SLOW", "1") // the map runs until it is cancelled, then sent 3 requests
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		_ = s.serve(inR, outW)
		outW.Close()
	}()
	msgs := make(chan map[string]any, 16)
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var m map[string]any
			_ = json.Unmarshal(sc.Bytes(), &m)
			msgs <- m
		}
		close(msgs)
	}()
	write := func(line string) { _, _ = io.WriteString(inW, line+"\n") }
	type status struct {
		Budget   struct{ Limit, Used, Left int64 }
		InFlight struct {
			Count    int
			Reserved int64
			Calls    []struct {
				Command     string
				MaxRequests int64 `json:"max_requests"`
			}
		} `json:"in_flight"`
	}
	statusAs := func(id int) status {
		t.Helper()
		write(`{"jsonrpc":"2.0","id":` + string(rune('0'+id)) + `,"method":"tools/call","params":{"name":"azhaq_status","arguments":{}}}`)
		for {
			select {
			case m := <-msgs:
				if m["id"] != float64(id) {
					continue
				}
				res, _ := m["result"].(map[string]any)
				content, _ := res["content"].([]any)
				var st status
				if len(content) == 0 {
					t.Fatalf("status %v", m)
				}
				text, _ := content[0].(map[string]any)["text"].(string)
				if err := json.Unmarshal([]byte(text), &st); err != nil {
					t.Fatalf("status %q: %v", text, err)
				}
				return st
			case <-time.After(10 * time.Second):
				t.Fatal("no status answer")
			}
		}
	}

	write(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"azhaq_map","arguments":{"url":"http://127.0.0.1/","workspace":"a"}}}`)
	write(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"azhaq_map","arguments":{"url":"http://127.0.0.1/","workspace":"b"}}}`) // waits for the slot
	for i := 0; ; i++ {                                                                                                                           // the first map has started
		if _, err := os.Stat(filepath.Join(dir, "args")); err == nil {
			break
		}
		if i > 200 {
			t.Fatal("the map did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	st := statusAs(3)
	if st.Budget.Used != 0 || st.Budget.Limit != 20 || st.InFlight.Count != 1 || st.InFlight.Reserved != 20 ||
		len(st.InFlight.Calls) != 1 || st.InFlight.Calls[0].Command != "run" || st.InFlight.Calls[0].MaxRequests != 20 {
		t.Errorf("status while the map runs: %+v", st)
	}

	write(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	write(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}`)
	var end status
	for i := 0; i < 100; i++ {
		if end = statusAs(4 + i%5); end.InFlight.Count == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if end.InFlight.Count != 0 || end.Budget.Used != 3 || end.Budget.Left != 17 {
		t.Errorf("status after the map ended: %+v", end)
	}
	inW.Close()
	for range msgs {
	}
}
