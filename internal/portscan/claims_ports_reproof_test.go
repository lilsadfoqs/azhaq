package portscan

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// The default set is the top 100 and 63 ports more, the usual ports of the
// services azhaq names, and the top 100 alone leaves those 63 out: so
// -p top-100 does not ask Redis's, MongoDB's, memcached's or Kafka's port.
func TestTheTopHundredAloneLeavesOutThePortsOfTheServicesAzhaqNames(t *testing.T) {
	top, err := Ports("top-100")
	if err != nil {
		t.Fatal(err)
	}
	def := DefaultPorts()
	if len(top) != 100 || len(def) != 163 {
		t.Fatalf("top-100 has %d ports and the default set %d, want 100 and 163", len(top), len(def))
	}
	more := 0
	for _, p := range def {
		if !slices.Contains(top, p) {
			more++
		}
	}
	if more != 63 {
		t.Errorf("the default set has %d ports the top 100 lacks, want 63", more)
	}
	for _, p := range []int{6379, 27017, 11211, 9092} {
		if slices.Contains(top, p) || !slices.Contains(def, p) {
			t.Errorf("port %d: in the top 100 %v, in the default set %v; want out of the first and in the second", p, slices.Contains(top, p), slices.Contains(def, p))
		}
	}
}

// Each probe line comes after the line of the connection it was written to,
// names its protocol, and for HTTP its method and a target with the path:
// the HEAD / of an HTTP port, and of a silent port the HEAD, the requests
// of the other protocols and the GET / of the last step.
func TestEveryProbeLineComesAfterItsConnectionAndNamesWhatWasSent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(l)
	defer ledger.Use(nil)
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
							return
						}
					}
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
	time.Sleep(1500 * time.Millisecond)
	l.Close()

	firstConn := map[string]int64{} // ip:port → seq of its tcp line
	type probe struct {
		seq  int64
		addr string
		e    ledger.Entry
	}
	var probes []probe
	_ = ledger.Read(path, func(e ledger.Entry) error {
		switch e.Kind {
		case "tcp":
			if _, ok := firstConn[e.Target]; !ok {
				firstConn[e.Target] = e.Seq
			}
		case ledger.KindProbe:
			addr := e.Target
			if e.Proto == "http" || e.Proto == "https" {
				u, err := url.Parse(e.Target)
				if err != nil {
					return err
				}
				addr = u.Host
			}
			probes = append(probes, probe{e.Seq, addr, e})
		}
		return nil
	})
	if len(probes) < 10 {
		t.Fatalf("%d probe lines", len(probes))
	}
	heads := map[string]bool{}
	gets := 0
	for _, p := range probes {
		seq, ok := firstConn[p.addr]
		if !ok || seq >= p.seq {
			t.Errorf("probe %d (%s %s) has no tcp line of %s before it (it is at %d, ok %v)", p.seq, p.e.Proto, p.e.Method, p.addr, seq, ok)
		}
		if p.e.Proto == "" {
			t.Errorf("probe %d names no protocol: %+v", p.seq, p.e)
		}
		if p.e.Proto == "http" {
			u, _ := url.Parse(p.e.Target)
			if u.Path != "/" || (p.e.Method != "HEAD" && p.e.Method != "GET") {
				t.Errorf("an HTTP probe is %s %s, want HEAD or GET of /", p.e.Method, p.e.Target)
			}
			if p.e.Method == "HEAD" {
				heads[p.addr] = true
			} else {
				gets++
			}
		}
	}
	for _, port := range []int{web, silent} {
		if !heads["127.0.0.1:"+strconv.Itoa(port)] {
			t.Errorf("port %d has no HEAD / probe", port)
		}
	}
	if gets != 1 {
		t.Errorf("%d GET / probes, want the one of the silent port (step 5)", gets)
	}
}
