package portscan

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// benchListeners starts n loopback listeners that accept and close, and
// returns their ports.
func benchListeners(b *testing.B, n int) []int {
	b.Helper()
	var ports []int
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { ln.Close() })
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	return ports
}

// BenchmarkFullRangeConnect is a connect scan of every TCP port of the
// loopback host, no service naming, with the ledger recording each connect:
// the cost of the connect path alone, as nmap -sT -p- is run for comparison.
func BenchmarkFullRangeConnect(b *testing.B) {
	open := benchListeners(b, 4)
	l, err := ledger.Open(filepath.Join(b.TempDir(), "l.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	ledger.Use(l)
	defer func() { ledger.Use(nil); l.Close() }()
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := &Scanner{Rate: 1e6, Detect: DetectNone, Retries: -1}
		r, err := s.ScanEach(context.Background(), "127.0.0.1", "127.0.0.1", ports)
		if err != nil {
			b.Fatal(err)
		}
		for _, p := range open {
			found := false
			for _, o := range r.Open {
				found = found || o.Port == p
			}
			if !found {
				b.Fatalf("open port %d not found", p)
			}
		}
	}
}
