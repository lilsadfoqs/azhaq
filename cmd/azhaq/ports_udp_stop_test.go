package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// udpStandIn binds a UDP port on 127.0.0.1 that counts what it reads; it
// answers when reply is set.
func udpStandIn(t *testing.T, reply string) (port int, reads *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	reads = new(atomic.Int32)
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			reads.Add(1)
			if reply != "" {
				pc.WriteTo([]byte(reply), from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, reads
}

// A UDP scan a request cap stops prints what it has, an answered port and
// the silent ones asked so far, and resuming under the same cap goes on
// from there: each silent port is asked its four requests in all, and the
// scan finishes.
func TestPortsUDPStoppedScanKeepsRowsAndResumeFinishes(t *testing.T) {
	t.Chdir(t.TempDir())
	answering, answerReads := udpStandIn(t, "hello")
	quietA, readsA := udpStandIn(t, "")
	quietB, readsB := udpStandIn(t, "")
	closed := deadUDPPort(t)
	spec := fmt.Sprintf("%d,%d,%d,%d", answering, quietA, quietB, closed)

	out, rep, code := runContract(t, "ports", "-host", "127.0.0.1", "-p", "none", "-pu", spec, "-max-requests", "4", "-allow", "127.0.0.1", "-db", "u.db")
	if code != exitLimit {
		t.Fatalf("exit %d, want %d\n%+v", code, exitLimit, rep)
	}
	if !strings.Contains(out, fmt.Sprintf(`"port":%d`, answering)) || rep.Results != 2 || rep.Counts["open"] != 1 || rep.Counts["open|filtered"] != 2 {
		t.Errorf("a stopped scan printed %d results, counts %v\n%s", rep.Results, rep.Counts, out)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "not final") {
		t.Errorf("the summary does not say the silent ports are not final: %v", rep.Notes)
	}
	var finished bool
	for i := 0; i < 5 && !finished; i++ {
		_, rep, code = runContract(t, "resume", "-db", "u.db", "-max-requests", "4")
		finished = code == exitOK
		if code != exitOK && code != exitLimit {
			t.Fatalf("resume exit %d\n%+v", code, rep)
		}
	}
	if !finished {
		t.Fatal("resuming under the same cap never finished the scan")
	}
	if answerReads.Load() != 1 || readsA.Load() != 4 || readsB.Load() != 4 {
		t.Errorf("datagrams read: answering %d, silent %d and %d; want 1, 4 and 4", answerReads.Load(), readsA.Load(), readsB.Load())
	}
}

func deadUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	p := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return p
}
