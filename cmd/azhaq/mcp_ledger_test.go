package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// The tools that name no workspace write the server's ledger, and the
// summaries' requests add up to the lines to targets of every ledger the
// server wrote, which azhaq ledger -verify takes as intact and sealed.
func TestMCPStatelessToolsWriteTheServerLedger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>x</title>`))
	}))
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no TCP: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &mcpServer{exe: exe, dir: filepath.Join(dir, "ws"), lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 100}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	requests := func(tool string, args map[string]any) int64 {
		t.Helper()
		text, isErr := callText(t, s, tool, args)
		var got struct {
			Summary struct{ Requests int64 }
		}
		if isErr || json.Unmarshal([]byte(text), &got) != nil {
			t.Fatalf("%s: %v %s", tool, isErr, text)
		}
		return got.Summary.Requests
	}
	var total int64
	total += requests("azhaq_probe", map[string]any{"targets": []any{srv.URL}})
	total += requests("azhaq_ports", map[string]any{"hosts": []any{"127.0.0.1"}, "ports": port})
	total += requests("azhaq_probe", map[string]any{"targets": []any{srv.URL}})
	if total < 3 {
		t.Fatalf("the calls sent %d requests, want at least 3", total)
	}

	files, _ := filepath.Glob(filepath.Join(s.dir, "*.ledger.jsonl"))
	if len(files) != 1 || filepath.Base(files[0]) != "server.ledger.jsonl" {
		t.Fatalf("the server wrote %v, want %s", files, "server.ledger.jsonl")
	}
	var lines int64
	if err := ledger.Read(files[0], func(e ledger.Entry) error {
		if e.Counted() {
			lines++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if lines != total {
		t.Errorf("the summaries count %d requests and the server's ledger lists %d lines to targets", total, lines)
	}
	if c, err := ledger.Verify(files[0]); err != nil || c.Seals != 3 {
		t.Errorf("the ledger is not intact and sealed once per call: %+v %v", c, err)
	}
	text, _ := callText(t, s, "azhaq_status", nil)
	var st struct{ Ledger string }
	if json.Unmarshal([]byte(text), &st) != nil || !strings.HasSuffix(st.Ledger, "server.ledger.jsonl") || !filepath.IsAbs(st.Ledger) {
		t.Errorf("azhaq_status does not name the ledger: %s", text)
	}
}

// Two calls that write the server's ledger never run together: its chain
// has one writer.
func TestMCPServerLedgerHasOneWriterAtATime(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	script := `#!/bin/sh
if ! mkdir "$FAKE_DIR/busy" 2>/dev/null; then touch "$FAKE_DIR/overlap"; fi
sleep 0.2
rmdir "$FAKE_DIR/busy" 2>/dev/null
echo '{"type":"summary","command":"probe","exit":0,"requests":0}' >&2
`
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DIR", dir)
	s := &mcpServer{exe: exe, dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.runLedgered(context.Background(), nil, false, "subs", "-json"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := os.Stat(filepath.Join(dir, "overlap")); err == nil {
		t.Error("two commands wrote the server's ledger at once")
	}
}

// subs takes -ledger FILE: with no workspace, it is what a server gives a
// call that names none.
func TestSubsWritesTheLedgerItIsGiven(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	cmd := exec.Command(os.Args[0], "subs", "-d", "localhost.test", "-sources", "none", "-ledger", path, "-json", "-silent")
	cmd.Env = append(os.Environ(), "AZHAQ_TEST_AS_MAIN=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if c, err := ledger.Verify(path); err != nil || c.Seals != 1 {
		t.Errorf("subs -ledger did not write a sealed ledger: %+v %v", c, err)
	}
}
