package contract

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A run stopped by its deadline or by the kill file lists what it sent and
// no more: the requests of its summary, the lines of its ledger and what
// reached the other end are one number.

// stopWords is a wordlist longer than any of these runs gets through.
func stopWords(l *Labs) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "w%03d\n", i)
	}
	l.File("words.txt", b.String())
}

// ledgerTargetLines is the non-seal lines to targets of the ledger at name.
func ledgerTargetLines(l *Labs, name string) int {
	return ledgerSent(readLedger(l.T, filepath.Join(l.Dir, name))).N
}

// sameNumber fails unless the summary, the ledger and the wire agree.
func sameNumber(v *Inv, l *Labs, r Result, name string, wire int) {
	lines := ledgerTargetLines(l, name)
	v.Equal("summary requests, against the non-seal lines of the ledger", r.Summary.Requests, int64(lines))
	v.Equal("ledger lines, against the requests the proxy saw", int64(lines), int64(wire))
}

func TestStopBoundaryHTTP(t *testing.T) {
	for _, c := range []struct {
		name  string
		flags []string
		kill  time.Duration // the kill file appears after this long; zero: not at all
		want  int           // the exit code
	}{
		{"a short -timeout while paced", []string{"-rate", "2", "-timeout", "1s"}, 0, 4},
		{"a short -timeout at a higher rate", []string{"-rate", "7", "-timeout", "700ms"}, 0, 4},
		{"the kill file while paced", []string{"-rate", "5"}, 900 * time.Millisecond, 4},
		{"the kill file at a low rate", []string{"-rate", "2"}, 1300 * time.Millisecond, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			stopWords(l)
			args := []string{"dirs", "-u", l.Site.URL + "/", "-w", "words.txt", "-proxy", l.Proxy.URL, "-ledger", "l.jsonl", "-kill-file", "k.stop"}
			args = append(args, c.flags...)
			if c.kill > 0 {
				time.AfterFunc(c.kill, func() { _ = os.WriteFile(filepath.Join(l.Dir, "k.stop"), nil, 0o644) })
			}
			r := RunRaw(t, l.Dir, nil, append(args, "-json")...)
			if !r.Has {
				t.Fatalf("no summary (exit %d)\n%s", r.Code, r.Stderr)
			}
			v := newInv(t, "")
			if r.Code != c.want {
				v.Errorf("exit %d, want %d", r.Code, c.want)
			}
			sameNumber(v, l, r, "l.jsonl", l.Proxy.Wire.Total())
			v.Done()
		})
	}
}

// A port scan stopped by the kill file lists the connects it made: its
// ledger holds one line for each connection the listeners accepted, and the
// summary counts as many.
func TestStopBoundaryTCP(t *testing.T) {
	for _, c := range []struct {
		name  string
		rate  string
		after int // the kill file appears once the ledger holds this many lines
	}{
		{"a paced scan", "300", 60},
		{"a batched scan", "2000", 120},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			wire := newWire()
			var ports []string
			var addrs []string
			for i := 0; i < 400; i++ {
				ln := listenCountedOn(t, wire, stopHost)
				addrs = append(addrs, ln.Addr)
				ports = append(ports, portOf(ln.Addr))
			}
			go killAfterLines(l.Dir, "l.jsonl", "k.stop", c.after)
			r := RunRaw(t, l.Dir, nil, "ports", "-host", stopHost, "-p", strings.Join(ports, ","), "-detect", "none",
				"-rate", c.rate, "-allow", stopHost, "-ledger", "l.jsonl", "-kill-file", "k.stop", "-json")
			if !r.Has {
				t.Fatalf("no summary (exit %d)\n%s", r.Code, r.Stderr)
			}
			time.Sleep(200 * time.Millisecond) // the listeners finish accepting
			sent := ledgerSent(readLedger(t, filepath.Join(l.Dir, "l.jsonl")))
			v := newInv(t, "")
			if r.Code != 4 {
				v.Errorf("exit %d, want 4: the kill file came before the scan ended (a timing of the test, or the scan finished first)", r.Code)
			}
			if sent.N == 0 || sent.N >= len(addrs) {
				v.Errorf("%d connects of %d: the scan was not stopped in the middle", sent.N, len(addrs))
			}
			v.Equal("summary requests, against the connect lines of the ledger", r.Summary.Requests, int64(sent.N))
			accepted := wire.TCP()
			if d := diff("ledger", sent.TCP, "accepted", accepted); d != "" {
				v.Errorf("the connects the ledger lists and the connections the listeners accepted differ (another process connecting to these ports at the same time would show here):\n%s", d)
			}
			v.Done()
		})
	}
}

// killAfterLines writes the kill file once the ledger holds n lines.
func killAfterLines(dir, ledger, kill string, n int) {
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		raw, err := os.ReadFile(filepath.Join(dir, ledger))
		if err == nil && strings.Count(string(raw), "\n") >= n {
			_ = os.WriteFile(filepath.Join(dir, kill), nil, 0o644)
			return
		}
	}
}

// stopHost is a loopback address of its own: the listeners of the scan are not
// asked by anything else that scans 127.0.0.1 on the machine meanwhile.
const stopHost = "127.77.31.9"

// listenCountedOn is listenCounted on the address host; it closes each connection at once.
func listenCountedOn(t testing.TB, wire *Wire, host string) *Counted {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Skipf("no TCP on %s: %v", host, err)
	}
	c := &Counted{Addr: ln.Addr().String(), Wire: wire, ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wire.addTCP(c.Addr)
			conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}
