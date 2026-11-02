package portscan

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// Every connect the scanner makes is one ledger entry: the count its Take
// hook saw and the ports of the entries agree.
func TestEveryConnectIsRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)

	var accepted atomic.Int32
	var ports []int
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				c.Write([]byte("SSH-2.0-test\r\n")) // speaks first: no HTTP probe follows
				c.Close()
			}
		}()
	}
	for p := 1; p <= 60; p++ { // closed ports, most of them
		ports = append(ports, p)
	}
	var takes atomic.Int32
	s := &Scanner{Take: func() error { takes.Add(1); return nil }}
	if _, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", ports); err != nil {
		t.Fatal(err)
	}
	l.Close()
	got := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "tcp" && e.Host == "localhost" {
			got++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != int(takes.Load()) || got != len(ports) {
		t.Fatalf("ledger has %d tcp entries, the scanner took %d, %d ports were given", got, takes.Load(), len(ports))
	}
	if accepted.Load() != 3 {
		t.Fatalf("the listeners accepted %d connections, want 3", accepted.Load())
	}
}

// The connects of a fast scan are written to the ledger a batch at a time,
// each a line before its connect, none twice and none missing.
func TestFastScanWritesItsConnectsInBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	t.Cleanup(func() { ledger.Use(nil); l.Close() })
	var ports []int
	for p := 20000; p < 20640; p++ {
		ports = append(ports, p)
	}
	s := &Scanner{Rate: 20000, Detect: DetectNone}
	if _, err := s.ScanEach(t.Context(), "", "127.0.0.1", ports); err != nil {
		t.Fatal(err)
	}
	if n := l.Count(); n != 640 {
		t.Errorf("%d lines for 640 connects", n)
	}
	if n := l.Flushes(); n > 640/8 {
		t.Errorf("%d writes for 640 connects", n)
	}
	seen := map[string]int{}
	_ = ledger.Read(path, func(e ledger.Entry) error { seen[e.Target]++; return nil })
	for _, p := range ports {
		if seen[net.JoinHostPort("127.0.0.1", strconv.Itoa(p))] != 1 {
			t.Fatalf("port %d is in the ledger %d times", p, seen[net.JoinHostPort("127.0.0.1", strconv.Itoa(p))])
		}
	}
}
