package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A -stream run with ports that reaches its request budget before the web
// reserve is held stops with the limit exit and a summary, not a panic.
func TestRunStreamWithPortsStopsAtTheBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><a href=/a>a</a><a href=/b>b</a></html>"))
	}))
	t.Cleanup(srv.Close)
	var ports []string
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("220 ready\r\n"))
				_ = c.Close()
			}
		}()
		ports = append(ports, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	}
	t.Chdir(t.TempDir())
	_, stderr, code := cli(t, "run", "-url", srv.URL+"/", "-ports", strings.Join(ports, ","), "-stream", "-no-paths", "-no-favicon", "-no-tech",
		"-sources", "none", "-max-requests", "5", "-db", "s.db", "-ledger", "s.ledger")
	if strings.Contains(stderr, "panic") {
		t.Fatalf("panic:\n%s", stderr)
	}
	if code != exitLimit || !strings.Contains(stderr, "stopped: the request budget of 5 is spent") || !strings.Contains(stderr, "sealed ") {
		t.Errorf("exit %d, want %d with the budget's stop and a sealed ledger:\n%s", code, exitLimit, stderr)
	}
}
