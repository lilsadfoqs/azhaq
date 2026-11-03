package main

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// sweepLab is a /29 of loopback addresses with a service on the same port
// of .2 (the one the operator names), .5 (one they would not have named)
// and .6; it counts the connects each address got.
type sweepLab struct {
	port  string
	mu    sync.Mutex
	dials map[string]int
}

func newSweepLab(t *testing.T) *sweepLab {
	t.Helper()
	lab := &sweepLab{dials: map[string]int{}}
	for i, host := range []string{"127.7.7.2", "127.7.7.5", "127.7.7.6"} {
		addr := host + ":0"
		if i > 0 {
			addr = net.JoinHostPort(host, lab.port)
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { l.Close() })
		if i == 0 {
			lab.port = fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				lab.mu.Lock()
				lab.dials[host]++
				lab.mu.Unlock()
				c.Close()
			}
		}()
	}
	return lab
}

func (l *sweepLab) dialed(host string) int {
	time.Sleep(100 * time.Millisecond)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dials[host]
}

// portRows are the addresses a ports -json run listed an open port on.
func portRows(t *testing.T, out string) []string {
	t.Helper()
	var ips []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var row struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.IP != "" {
			ips = append(ips, row.IP)
		}
	}
	sort.Strings(ips)
	return ips
}

func notesOf(sum map[string]any) string {
	n, _ := sum["notes"].([]any)
	return fmt.Sprint(n)
}

// A range in -allow with one address named: ports scans the address named
// and says how much of the range it left; -sweep scans the rest, and
// nothing outside -allow or in -deny.
func TestPortsSweepCoversTheAllowedRange(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := newSweepLab(t)
	base := []string{"ports", "-host", "127.7.7.2", "-p", lab.port, "-json"}

	out, errOut, code := cli(t, append(base, "-allow", "127.7.7.0/29")...)
	sum := sumMap(t, errOut)
	if got := portRows(t, out); code != exitOK || len(got) != 1 || got[0] != "127.7.7.2" {
		t.Fatalf("without -sweep: exit %d, rows %v", code, got)
	}
	if !strings.Contains(notesOf(sum), "holds 8 addresses and the targets name 1 of them: -sweep covers the other 7") {
		t.Errorf("no lead for the 7 addresses left: %v", sum["notes"])
	}
	if lab.dialed("127.7.7.5") != 0 {
		t.Errorf("the unnamed address was connected to without -sweep")
	}

	out, errOut, code = cli(t, append(base, "-allow", "127.7.7.0/29", "-sweep")...)
	sum = sumMap(t, errOut)
	got := portRows(t, out)
	if code != exitOK || fmt.Sprint(got) != "[127.7.7.2 127.7.7.5 127.7.7.6]" {
		t.Fatalf("-sweep: exit %d, rows %v", code, got)
	}
	if c, _ := sum["counts"].(map[string]any); c["addresses"] != float64(8) {
		t.Errorf("the summary does not count the 8 addresses of the range: %v", sum["counts"])
	}
	if strings.Contains(notesOf(sum), "-sweep covers") {
		t.Errorf("the lead is still given when the range is covered: %v", sum["notes"])
	}

	// A tighter -allow bounds the sweep, and so does -deny.
	before5, before6 := lab.dialed("127.7.7.5"), lab.dialed("127.7.7.6")
	out, errOut, code = cli(t, append(base, "-allow", "127.7.7.0/30", "-sweep")...)
	sum = sumMap(t, errOut)
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.7.7.2]" {
		t.Fatalf("-allow 127.7.7.0/30 -sweep: exit %d, rows %v", code, got)
	}
	if c, _ := sum["counts"].(map[string]any); c["addresses"] != float64(4) {
		t.Errorf("a /30 is 4 addresses: %v", sum["counts"])
	}
	out, _, code = cli(t, append(base, "-allow", "127.7.7.0/29", "-deny", "127.7.7.5", "-sweep")...)
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.7.7.2 127.7.7.6]" {
		t.Fatalf("-deny 127.7.7.5 -sweep: exit %d, rows %v", code, got)
	}
	if lab.dialed("127.7.7.5") != before5 || lab.dialed("127.7.7.6") != before6+1 {
		t.Errorf("connects: .5 went from %d to %d, .6 from %d to %d", before5, lab.dialed("127.7.7.5"), before6, lab.dialed("127.7.7.6"))
	}
}

// -sweep is a target of its own: the scope's ranges, nothing else named.
func TestPortsSweepNeedsARange(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := newSweepLab(t)
	out, _, code := cli(t, "ports", "-sweep", "-allow", "127.7.7.4/30", "-p", lab.port, "-json")
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.7.7.5 127.7.7.6]" {
		t.Errorf("-sweep alone: exit %d, rows %v", code, got)
	}
	for _, args := range [][]string{
		{"ports", "-sweep", "-host", "127.7.7.2", "-p", lab.port},
		{"ports", "-sweep", "-host", "127.7.7.2", "-allow", "example.test", "-p", lab.port},
		{"run", "-sweep", "-url", "http://127.7.7.2:" + lab.port + "/", "-allow", "example.test"},
	} {
		if _, errOut, code := cli(t, args...); code != exitUsage || !strings.Contains(errOut, "-sweep") {
			t.Errorf("%v: exit %d\n%s", args, code, errOut)
		}
	}
}

// run: the same range, the same probes: a seeded run finds the service on
// the named address; with -sweep the ledger and the summary hold the whole
// range, and a tighter -allow keeps the rest out.
func TestRunSweepCoversTheAllowedRange(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	lab := newSweepLab(t)
	run := func(name string, extra ...string) (map[string]any, string) {
		led := filepath.Join(dir, name+".ledger.jsonl")
		args := append([]string{"run", "-url", "http://127.7.7.2:" + lab.port + "/", "-ports", lab.port, "-sources", "none",
			"-db", filepath.Join(dir, name+".db"), "-ledger", led, "-json", "-quiet"}, extra...)
		_, errOut, code := cli(t, args...)
		if code != exitOK && code != exitPartial {
			t.Fatalf("%s: exit %d\n%s", name, code, errOut)
		}
		return sumMap(t, errOut), led
	}

	sum, led := run("seeded", "-allow", "127.7.7.0/29")
	if n := ledgerHosts(t, led, "127.7.7.2"); n == 0 || ledgerHosts(t, led, "127.7.7.5") != 0 {
		t.Errorf("without -sweep the ledger names .5 %d times", ledgerHosts(t, led, "127.7.7.5"))
	}
	if !strings.Contains(notesOf(sum), "holds 8 addresses and the targets name 1 of them") {
		t.Errorf("no lead: %v", sum["notes"])
	}

	sum, led = run("swept", "-allow", "127.7.7.0/29", "-sweep")
	if ledgerHosts(t, led, "127.7.7.5") == 0 || ledgerHosts(t, led, "127.7.7.6") == 0 {
		t.Errorf("-sweep did not ask the other addresses of the range")
	}
	if c, _ := sum["counts"].(map[string]any); c["ports"] != float64(3) {
		t.Errorf("the three open ports are not in the summary: %v", sum["counts"])
	}

	_, led = run("tight", "-allow", "127.7.7.0/30", "-sweep")
	if ledgerHosts(t, led, "127.7.7.5") != 0 || ledgerHosts(t, led, "127.7.7.6") != 0 {
		t.Errorf("-allow 127.7.7.0/30 -sweep reached outside it")
	}
}

// ledgerHosts counts the ledger's lines that name the host.
func ledgerHosts(t *testing.T, path, host string) int {
	t.Helper()
	n := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if strings.Contains(e.Target, host) {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// An IPv6 range in -allow is not swept: ports says so in a note and asks
// none of its addresses, while the IPv4 range beside it is.
func TestSweepLeavesAnIPv6RangeAloneWithANote(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := newSweepLab(t)
	out, errOut, code := cli(t, "ports", "-sweep", "-allow", "127.7.7.4/30", "-allow", "2001:db8::/120", "-p", lab.port, "-json")
	sum := sumMap(t, errOut)
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.7.7.5 127.7.7.6]" {
		t.Errorf("exit %d, rows %v: the IPv4 range was not swept", code, got)
	}
	if !strings.Contains(notesOf(sum), "-sweep leaves the IPv6 range 2001:db8::/120 alone: name it as a target to scan it") {
		t.Errorf("no note about the IPv6 range: %v", sum["notes"])
	}
	if c, _ := sum["counts"].(map[string]any); c["addresses"] != float64(4) {
		t.Errorf("only the 4 IPv4 addresses are counted: %v", sum["counts"])
	}
}
