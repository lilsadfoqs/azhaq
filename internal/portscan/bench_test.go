package portscan

import (
	"context"
	"net"
	"path/filepath"
	"slices"
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
// loopback host, no service naming: the cost of the connect path alone, as
// nmap -sT -p- is run for comparison. "ledger" records each connect, as a
// run does; "no ledger" is what writing the lines costs less.
func BenchmarkFullRangeConnect(b *testing.B) {
	open := benchListeners(b, 4)
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	for _, withLedger := range []bool{true, false} {
		name := "no ledger"
		if withLedger {
			name = "ledger"
		}
		b.Run(name, func(b *testing.B) {
			if withLedger {
				l, err := ledger.Open(filepath.Join(b.TempDir(), "l.jsonl"))
				if err != nil {
					b.Fatal(err)
				}
				ledger.Use(l)
				defer func() { ledger.Use(nil); l.Close() }()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Retries off: a listener of this machine that drops connects would
				// cost a pass of its own.
				s := &Scanner{Rate: 1e6, Detect: DetectNone, Retries: -1}
				r, err := s.ScanEach(context.Background(), "127.0.0.1", "127.0.0.1", ports)
				if err != nil {
					b.Fatal(err)
				}
				for _, p := range open {
					if !slices.ContainsFunc(r.Open, func(o Open) bool { return o.Port == p }) {
						b.Fatalf("open port %d not found", p)
					}
				}
			}
		})
	}
}
