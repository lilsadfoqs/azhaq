package main

import (
	"net"
	"strconv"
	"testing"
)

// Every failure the probe summary counts is named in failed: a name with
// no address beside a refused connection.
func TestProbeNamesADNSFailureInFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close() // nothing listens there now
	dir := t.TempDir()
	list := writeFile(t, dir, "hosts.txt", "no-such-azhaq.invalid\n"+refused+"\n")
	t.Chdir(dir)
	_, rep, _ := runContract(t, "probe", "-l", list)
	named := map[string]bool{}
	for _, f := range rep.Failed {
		for _, x := range f.Targets {
			named[x] = true
		}
	}
	if rep.Failures != 2 || !named["no-such-azhaq.invalid"] {
		t.Errorf("failures %d, failed %+v: the name with no address is counted and named", rep.Failures, rep.Failed)
	}
}
