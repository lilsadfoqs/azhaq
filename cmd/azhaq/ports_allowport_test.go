package main

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// listenCount is a loopback listener that counts the connects it gets.
func listenCount(t *testing.T) (port string, dialed *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { l.Close() })
	dialed = new(atomic.Int32)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), dialed
}

// Every port asked is outside the scope when -allow names the host on other
// ports only: exit 2 before anything is sent, as for a host outside it, and
// the summary counts no port it did not ask. A port the scope allows still
// runs, and the ones it holds out are noted.
func TestPortsEveryPortOutsideAllowIsUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	asked, dialed := listenCount(t)
	allowed, dialedAllowed := listenCount(t)
	for _, args := range [][]string{
		{"ports", "-host", "127.0.0.1:" + asked, "-allow", "127.0.0.1:" + allowed, "-detect", "none", "-json"},
		{"ports", "-host", "127.0.0.1", "-p", asked, "-allow", "127.0.0.1:" + allowed, "-detect", "none", "-json"},
	} {
		out, errOut, code := cli(t, args...)
		if code != exitUsage || !strings.Contains(errOut, "every target is outside the scope (1 left out): 127.0.0.1") {
			t.Errorf("%v: exit %d\n%s", args, code, errOut)
		}
		if strings.Contains(out+errOut, "-p full") || strings.Contains(errOut, `"results":`) && !strings.Contains(errOut, `"results":0`) {
			t.Errorf("%v: the summary suggests or counts ports it did not ask:\n%s", args, errOut)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := dialed.Load() + dialedAllowed.Load(); n != 0 {
		t.Errorf("%d connects with every port outside the scope", n)
	}

	out, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", asked+","+allowed, "-allow", "127.0.0.1:"+allowed, "-detect", "none", "-json")
	if code != exitOK || strings.Count(out, `"port":`) != 1 || !strings.Contains(out, `"port":`+allowed) {
		t.Errorf("a port in scope: exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "1 ports on 1 addresses were not scanned") || strings.Contains(errOut, "-p full") {
		t.Errorf("the port held out is noted and no wider pass is offered:\n%s", errOut)
	}
	time.Sleep(100 * time.Millisecond)
	if dialed.Load() != 0 || dialedAllowed.Load() != 1 {
		t.Errorf("connects: %d to the port outside, %d to the port allowed", dialed.Load(), dialedAllowed.Load())
	}
}
