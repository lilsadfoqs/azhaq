package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A map the server's budget stopped is stopped in azhaq_status, with its
// tasks left, its requests and the call that resumes it, and a query of the
// workspace afterwards does not make it complete. A resume that finishes
// the work does.
func TestMCPStatusOfACappedMapComesFromTheWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		fmt.Sscanf(r.URL.Path, "/p%d", &n)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<title>p%d</title><a href="/p%d">a</a><a href="/p%d">b</a>`, n, n+1, n+2)
		if n > 6 {
			w.Write([]byte(`x`))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &mcpServer{exe: exe, dir: filepath.Join(dir, "ws"), lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 3}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	text, isErr := callText(t, s, "azhaq_map", map[string]any{"url": srv.URL + "/p1", "workspace": "w"})
	if isErr || !strings.Contains(text, `"exit":4`) {
		t.Fatalf("the map should stop at the budget: %v %s", isErr, text)
	}
	type row struct {
		Name, State, Detail, Resume string
		TasksLeft                   int `json:"tasks_left"`
		Requests                    int64
	}
	status := func() row {
		t.Helper()
		text, isErr := callText(t, s, "azhaq_status", nil)
		var got struct{ Workspaces []row }
		if isErr || json.Unmarshal([]byte(text), &got) != nil || len(got.Workspaces) != 1 {
			t.Fatalf("status: %v %s", isErr, text)
		}
		return got.Workspaces[0]
	}
	check := func(when string) {
		t.Helper()
		w := status()
		if w.State != "stopped by a limit" || w.TasksLeft == 0 || w.Requests < 1 || !strings.Contains(w.Resume, `azhaq_resume {"workspace":"w"}`) {
			t.Errorf("%s: %+v", when, w)
		}
	}
	check("after the capped map")
	if _, isErr := callText(t, s, "azhaq_query", map[string]any{"workspace": "w"}); isErr {
		t.Fatal("query failed")
	}
	check("after a query of the workspace")
	s.budget = 500
	for i := 0; i < 20 && status().State != "complete"; i++ {
		if text, isErr := callText(t, s, "azhaq_resume", map[string]any{"workspace": "w"}); isErr && !strings.Contains(text, "nothing to resume") {
			t.Fatalf("resume: %s", text)
		}
	}
	if w := status(); w.State != "complete" || w.TasksLeft != 0 || w.Requests <= 3 {
		t.Errorf("after the resumes: %+v", w)
	}
}
