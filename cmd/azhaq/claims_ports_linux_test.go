package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// stuckPort is a port on 127.0.0.1 whose accept queue is full: the next
// connect gets no answer, neither accepted nor refused.
func stuckPort(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skip(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skip(err)
	}
	sa, _ := syscall.Getsockname(fd)
	port := sa.(*syscall.SockaddrInet4).Port
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; ; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 150*time.Millisecond)
		if err != nil {
			return port
		}
		held = append(held, c)
		if i == 8 {
			t.Skip("the accept queue does not fill on this kernel")
		}
	}
}

// -retries asks a port that neither accepted nor refused once more by
// default, N more times with -retries N, never with -retries 0; each ask is
// a connect in the ledger and counted against -max-requests.
func TestPortsRetriesFlagSetsHowOftenASilentPortIsAskedAgain(t *testing.T) {
	t.Chdir(t.TempDir())
	port := stuckPort(t)
	for _, c := range []struct {
		extra []string
		want  int
	}{{nil, 2}, {[]string{"-retries", "0"}, 1}, {[]string{"-retries", "2"}, 3}} {
		led := fmt.Sprintf("r%d.jsonl", c.want)
		args := append([]string{"ports", "-host", "127.0.0.1", "-p", fmt.Sprint(port), "-detect", "none", "-connect-timeout", "150", "-json", "-ledger", led}, c.extra...)
		_, errOut, code := cli(t, args...)
		rep := lastReport(t, errOut)
		n := 0
		if err := ledger.Read(led, func(e ledger.Entry) error {
			if e.Kind == "tcp" && e.IsTarget() {
				n++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if code != exitOK || n != c.want || int(rep.Requests) != c.want {
			t.Errorf("%v: exit %d, %d connects in the ledger, %d in the summary, want %d", c.extra, code, n, rep.Requests, c.want)
		}
	}
	// The ask after the first counts against -max-requests.
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", fmt.Sprint(port), "-detect", "none", "-connect-timeout", "150", "-json", "-ledger", "off", "-max-requests", "1")
	if rep := lastReport(t, errOut); code != exitLimit || rep.Requests != 1 {
		t.Errorf("-max-requests 1: exit %d, %d requests: the second ask was not stopped by the cap", code, rep.Requests)
	}
}

// -wn scans only the addresses that accept or refuse a connect to 80 or 443:
// an address that answers neither is called down and its ports are not
// asked; -sn lists the up ones and asks no port.
func TestPortsWNScansOnlyTheAddressesThatAreUp(t *testing.T) {
	t.Chdir(t.TempDir())
	stuck := stuckPort(t) // 127.0.0.1 is silent on the discovery port
	saved := portscan.DiscoveryPorts
	portscan.DiscoveryPorts = []int{stuck}
	t.Cleanup(func() { portscan.DiscoveryPorts = saved })
	// The scanned port is open on 127.0.0.1 and on 127.0.0.2, which refuses the discovery port.
	var port string
	for i, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		addr := ip + ":0"
		if i > 0 {
			addr = ip + ":" + port
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { l.Close() })
		port = fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	base := []string{"ports", "-host", "127.0.0.0/30", "-p", port, "-detect", "none", "-connect-timeout", "150", "-json", "-ledger", "off"}
	out, _, code := cli(t, base...)
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.0.0.1 127.0.0.2]" {
		t.Fatalf("without -wn: exit %d, rows %v", code, got)
	}
	out, errOut, code := cli(t, append(base, "-wn")...)
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.0.0.2]" {
		t.Errorf("-wn: exit %d, rows %v, want only the address that is up", code, got)
	}
	if notes := fmt.Sprint(lastReport(t, errOut).Notes); !strings.Contains(notes, "1 addresses answered neither a connect to 80 nor to 443 (asked twice) and were not scanned") {
		t.Errorf("-wn does not say how many hosts were called down: %s", notes)
	}
	out, _, code = cli(t, append(base, "-sn")...)
	if code != exitOK || strings.Contains(out, `"port"`) || !strings.Contains(out, `"up":true`) || strings.Contains(out, `"ip":"127.0.0.1"`) {
		t.Errorf("-sn: exit %d, out %s", code, out)
	}
}
