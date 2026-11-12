package portscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"os"
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
	var got []string  // the hash of what each connection received
	var raws []string // what each received, in hex
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
					raws = append(raws, hex.EncodeToString(all))
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

	var bodies, listed, sent []string
	protos := map[string]int{}
	conns := 0
	_ = ledger.Read(path, func(e ledger.Entry) error {
		switch e.Kind {
		case "tcp":
			conns++
		case ledger.KindProbe:
			bodies = append(bodies, e.Body)
			sent = append(sent, e.Sent)
			if b, err := hex.DecodeString(e.Sent); err != nil || len(b) == 0 {
				t.Errorf("probe line %d has no bytes to replay: %q", e.Seq, e.Sent)
			} else if sum := sha256.Sum256(b); hex.EncodeToString(sum[:])[:16] != e.Body {
				t.Errorf("probe line %d: its sent bytes do not hash to its body", e.Seq)
			}
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
	// A replay of the ledger's probes sends what the listeners received.
	sort.Strings(raws)
	sort.Strings(sent)
	if strings.Join(raws, ",") != strings.Join(sent, ",") {
		t.Errorf("the ledger's sent bytes differ from what arrived:\nreceived %v\nlisted   %v", raws, sent)
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

// Every request a protocol of the scan sends fits in a ledger line's sent
// field, so no probe is listed by its hash alone.
func TestProbeRequestsFitTheLedgerLine(t *testing.T) {
	for _, p := range protocols {
		if p.request == nil {
			continue
		}
		if n := len(p.request(target{host: "host.example", port: 1234})); n > ledger.MaxSent {
			t.Errorf("%s sends %d bytes, over the %d a ledger line carries", p.name, n, ledger.MaxSent)
		}
	}
}

// BytesPerConnect, the plan's estimate of what a connect costs the ledger,
// is within a tenth of the mean tcp line a loopback scan writes. A scan of
// closed ports is what a full-range sweep mostly writes.
func TestLedgerBytesPerConnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Match = func(string) string { return "-allow 127.0.0.1" }
	ledger.Use(l)
	defer ledger.Use(nil)
	var ports []int
	for p := 20000; p < 20400; p++ {
		ports = append(ports, p)
	}
	ctx := ledger.WithCollector(context.Background(), "azhaq-ports")
	s := &Scanner{Timeout: 400 * time.Millisecond, Banner: -1}
	if _, err := s.ScanEach(ctx, "", "127.0.0.1", ports); err != nil {
		t.Fatal(err)
	}
	l.Close()
	var lines, size int
	f, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range bytes.SplitAfter(f, []byte("\n")) {
		if bytes.Contains(ln, []byte(`"kind":"tcp"`)) {
			lines++
			size += len(ln)
		}
	}
	if lines < len(ports) {
		t.Fatalf("%d tcp lines for %d ports", lines, len(ports))
	}
	mean := float64(size) / float64(lines)
	t.Logf("%d tcp lines, %.1f bytes each", lines, mean)
	if mean < 0.9*ledger.BytesPerConnect || mean > 1.1*ledger.BytesPerConnect {
		t.Errorf("a tcp line is %.1f bytes; ledger.BytesPerConnect is %d", mean, ledger.BytesPerConnect)
	}
}
