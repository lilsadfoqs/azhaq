package main

import (
	"io"
	"net"
	"strings"
	"testing"
)

// closedPort is a loopback port nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// socks5Refusing is a SOCKS5 proxy that answers every CONNECT with "connection
// refused": the proxy works and the target behind it refuses.
func socks5Refusing(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				io.ReadFull(c, buf[:int(buf[1])])
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:6])
				case 4:
					io.ReadFull(c, buf[:18])
				case 3:
					io.ReadFull(c, buf[:1])
					io.ReadFull(c, buf[:int(buf[0])+2])
				}
				c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // reply 5: connection refused
			}()
		}
	}()
	return l.Addr().String()
}

// A proxy that cannot be reached is a failure of the run, named, not a
// port that read as closed; a proxy that works and whose target refuses
// leaves the port closed, with no failure.
func TestPortsProxyFailureIsNotClosedPorts(t *testing.T) {
	dead := closedPort(t)
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "22,80", "-proxy", dead, "-allow", "127.0.0.1", "-json")
	sum := sumMap(t, errOut)
	if code != exitPartial || sum["failures"] == float64(0) {
		t.Fatalf("a dead proxy: exit %d, summary %v", code, sum)
	}
	if !strings.Contains(errOut, "-proxy "+dead+" failed") {
		t.Errorf("the failure does not name the proxy %s:\n%s", dead, errOut)
	}

	_, errOut, code = cli(t, "ports", "-host", "127.0.0.1", "-p", "22,80", "-proxy", socks5Refusing(t), "-allow", "127.0.0.1", "-json")
	sum = sumMap(t, errOut)
	if code != exitOK || sum["failures"] != float64(0) {
		t.Errorf("a proxy whose target refuses: exit %d, summary %v", code, sum)
	}
}

// A -source-ip that is not an address of this machine is a usage error before
// anything is sent, not a scan whose connects all fail.
func TestPortsSourceIPThatCannotBeBoundIsAUsageError(t *testing.T) {
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", "22,80", "-source-ip", "203.0.113.77", "-allow", "127.0.0.1", "-json")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d:\n%s", code, exitUsage, errOut)
	}
	if !strings.Contains(errOut, "203.0.113.77") || !strings.Contains(errOut, "-source-ip") {
		t.Errorf("the error does not name the address:\n%s", errOut)
	}
	if sum := sumMap(t, errOut); sum["requests"] != nil && sum["requests"] != float64(0) {
		t.Errorf("a connect was made: %v", sum["requests"])
	}
}
