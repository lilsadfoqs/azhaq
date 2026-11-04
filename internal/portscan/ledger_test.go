package portscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// Every write a port's identification makes on a connection has a probe
// line: behind a listener that logs what it receives, the hashes of what
// arrived are the lines' bodies, and the HTTP ones are listed by method and
// path. A TLS handshake is the connection's tcp line, not a probe.
func TestEveryProbeWrittenIsListed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)

	var mu sync.Mutex
	var got []string // the hash of what each connection received
	var reqs []string
	serve := func(answer bool) int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					var all []byte
					buf := make([]byte, 4096)
					for {
						_ = c.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
						n, err := c.Read(buf)
						all = append(all, buf[:n]...)
						if n > 0 && answer && bytes.HasPrefix(all, []byte("HEAD ")) {
							c.Write([]byte("HTTP/1.0 200 OK\r\nServer: probe-test\r\n\r\n"))
						}
						if err != nil {
							break
						}
					}
					if len(all) == 0 || all[0] == 0x16 { // nothing, or a TLS handshake
						return
					}
					sum := sha256.Sum256(all)
					mu.Lock()
					got = append(got, hex.EncodeToString(sum[:])[:16])
					if bytes.HasPrefix(all, []byte("HEAD ")) || bytes.HasPrefix(all, []byte("GET ")) {
						reqs = append(reqs, strings.Fields(string(all))[0]+" /")
					}
					mu.Unlock()
				}()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	web, silent := serve(true), serve(false)
	s := &Scanner{Banner: 100 * time.Millisecond, Timeout: 400 * time.Millisecond}
	if _, err := s.ScanEach(context.Background(), "", "127.0.0.1", []int{web, silent}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // the listeners read until their deadline
	l.Close()

	var bodies, listed []string
	protos := map[string]int{}
	conns := 0
	_ = ledger.Read(path, func(e ledger.Entry) error {
		switch e.Kind {
		case "tcp":
			conns++
		case ledger.KindProbe:
			bodies = append(bodies, e.Body)
			protos[e.Proto]++
			if e.Proto == "http" {
				u, _ := url.Parse(e.Target)
				listed = append(listed, e.Method+" "+u.Path)
			}
		}
		return nil
	})
	mu.Lock()
	defer mu.Unlock()
	sort.Strings(got)
	sort.Strings(bodies)
	if len(got) < 10 || strings.Join(got, ",") != strings.Join(bodies, ",") {
		t.Fatalf("the listeners received %d writes, the ledger lists %d probes:\nreceived %v\nlisted   %v", len(got), len(bodies), got, bodies)
	}
	sort.Strings(reqs)
	sort.Strings(listed)
	if len(reqs) != 3 || strings.Join(reqs, ",") != strings.Join(listed, ",") {
		t.Errorf("HTTP requests received %v, listed %v", reqs, listed)
	}
	if protos["redis"] == 0 || protos["http"] != 3 {
		t.Errorf("probe protocols %v", protos)
	}
	if conns < len(got) {
		t.Errorf("%d tcp lines for %d connections that were written to", conns, len(got))
	}
}
