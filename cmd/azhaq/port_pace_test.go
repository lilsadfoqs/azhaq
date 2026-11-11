package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// webOn127 is a web server on 127.0.0.1 for a run to be pointed at.
func webOn127(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>x</title>")
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/"
}

// timedRun runs azhaq with args and says how long it took.
func timedRun(t *testing.T, args ...string) time.Duration {
	t.Helper()
	t0 := time.Now()
	_, _, code := cli(t, args...)
	d := time.Since(t0)
	if code != exitOK && code != exitPartial {
		t.Fatalf("%v: exit %d", args, code)
	}
	return d
}

// -rate paces the connects of the port stage as it does the requests (#380):
// 10 connects at 5 a second take at least 1.8 s, on an address of 127/8 too.
func TestRatePacesTheConnectsOfARun(t *testing.T) {
	t.Chdir(t.TempDir())
	url := webOn127(t)
	base := []string{"run", "-url", url, "-allow", "127.0.0.1", "-passive", "-ports", "55555-55564", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "r.db"), "-json"}
	for _, c := range []struct {
		name  string
		extra []string
		min   time.Duration
	}{
		{"-rate", []string{"-rate", "5"}, 1800 * time.Millisecond},
		{"-port-rate alone", []string{"-port-rate", "5"}, 1800 * time.Millisecond},
		{"-rate under -port-rate", []string{"-rate", "5", "-port-rate", "1000"}, 1800 * time.Millisecond},
		{"-port-rate under -rate", []string{"-rate", "1000", "-port-rate", "5"}, 1800 * time.Millisecond},
		{"-rate over -port-min-rate", []string{"-rate", "5", "-port-min-rate", "1000"}, 1800 * time.Millisecond},
	} {
		if d := timedRun(t, append(append([]string{}, base...), c.extra...)...); d < c.min {
			t.Errorf("%s: 10 connects took %s, want at least %s", c.name, d, c.min)
		}
	}
	// No rate of any name: loopback is not paced.
	if d := timedRun(t, base...); d > time.Second {
		t.Errorf("loopback with no rate took %s: it is not to be paced", d)
	}
}

// The same on a swept range.
func TestRatePacesTheConnectsOfASweep(t *testing.T) {
	t.Chdir(t.TempDir())
	url := webOn127(t)
	args := []string{"run", "-url", url, "-allow", "127.0.0.0/29", "-sweep", "-passive", "-ports", "55555-55556", "-rate", "8",
		"-ledger", "off", "-db", filepath.Join(t.TempDir(), "r.db"), "-json"}
	if d := timedRun(t, args...); d < 1800*time.Millisecond {
		t.Errorf("16 connects at 8 a second took %s, want at least 1.8 s", d)
	}
}

// The plan says the pace of each stage.
func TestPlanSaysThePaceOfEachStage(t *testing.T) {
	t.Chdir(t.TempDir())
	out, _, _ := cli(t, "plan", "-url", "http://127.0.0.1:9/", "-allow", "127.0.0.1", "-rate", "5", "-port-rate", "900", "-ports", "80")
	if want := "pace: requests 5/s, connects 5/s, datagrams 5/s, DNS queries to the targets' name servers 5/s"; !strings.Contains(out, want) {
		t.Errorf("the plan does not say %q:\n%s", want, out)
	}
	out, _, _ = cli(t, "plan", "-url", "http://127.0.0.1:9/", "-allow", "127.0.0.1", "-ports", "80")
	if want := "pace: requests none, connects 1500/s, 127.0.0.1 unpaced"; !strings.Contains(out, want) {
		t.Errorf("the plan does not say %q:\n%s", want, out)
	}
}

func TestPortPaceIsTheLowerOfRateAndPortRate(t *testing.T) {
	for _, c := range []struct{ rate, port, want float64 }{
		{0, 0, 0}, {0, 700, 700}, {5, 0, 5}, {5000, 0, portscan.DefaultRate}, {5, 700, 5}, {700, 5, 5},
	} {
		if got := portPace(c.rate, c.port); got != c.want {
			t.Errorf("-rate %g -port-rate %g: %g, want %g", c.rate, c.port, got, c.want)
		}
	}
}

// tcpAsks is how many connects of a ledger went to each address and port.
func tcpAsks(t *testing.T, path string) map[string]int {
	t.Helper()
	asks := map[string]int{}
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind == "tcp" && e.IsTarget() {
			asks[e.Target]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return asks
}

func total(m map[string]int) (n int) {
	for _, v := range m {
		n += v
	}
	return n
}

// An address a target names and a swept range holds is asked once (#381):
// 8 addresses of 5 ports are 40 connects, as the estimate says.
func TestANamedAddressInASweptRangeIsAskedOnce(t *testing.T) {
	t.Chdir(t.TempDir())
	url := webOn127(t)
	led := filepath.Join(t.TempDir(), "l.jsonl")
	_, errOut, code := cli(t, "run", "-url", url, "-allow", "127.0.0.0/29", "-sweep", "-ports", "55555-55559", "-passive",
		"-ledger", led, "-db", filepath.Join(t.TempDir(), "r.db"), "-json")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d", code)
	}
	asks := tcpAsks(t, led)
	for target, n := range asks {
		if n != 1 {
			t.Errorf("%s was asked %d times", target, n)
		}
	}
	st := stagesOf(t, sumMap(t, errOut))["ports"]
	est, act := stageAmount(st, "estimate", "connects"), stageAmount(st, "actual", "connects")
	if got := total(asks); got != 40 || est != 40 || act != 40 {
		t.Errorf("the ledger has %d connects, the estimate %v, the summary %v: want 40 in all", got, est, act)
	}
}

// The default scan of a range asks pass 2 of an answered address once, though
// a target names it.
func TestADefaultScanAsksANamedAddressOfTheRangeOnce(t *testing.T) {
	t.Chdir(t.TempDir())
	var open net.Listener
	for _, p := range portscan.DefaultPorts() {
		if p < 1024 {
			continue
		}
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			open = ln
			break
		}
	}
	if open == nil {
		t.Skip("no port of the default scan is free on 127.0.0.1")
	}
	defer open.Close()
	go func() {
		for {
			c, err := open.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	url := webOn127(t)
	led := filepath.Join(t.TempDir(), "l.jsonl")
	_, _, code := cli(t, "run", "-url", url, "-allow", "127.0.0.0/30", "-sweep", "-ports", "default", "-passive", "-port-detect", "none",
		"-ledger", led, "-db", filepath.Join(t.TempDir(), "r.db"), "-json")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d", code)
	}
	asks := tcpAsks(t, led)
	// A silent port is asked again (a loopback connect now and then fails), so
	// the pairs are what is counted, and the asks beyond them are few.
	first := len(portscan.DefaultPorts())
	perIP := map[string]int{}
	for target := range asks {
		host, _, _ := net.SplitHostPort(target)
		perIP[host]++
	}
	for ip, n := range perIP {
		if n != 65535 && n > first+1 {
			t.Errorf("%s was asked %d ports: the first pass is %d, and an address that answered is asked 65535 in all", ip, n, first)
		}
	}
	if extra := total(asks) - len(asks); extra > 200 {
		t.Errorf("%d connects for %d pairs of address and port: an address is asked its ports again", total(asks), len(asks))
	}
}

// ports -rate already paces the connects, on loopback too.
func TestPortsRatePacesTheConnects(t *testing.T) {
	t.Chdir(t.TempDir())
	d := timedRun(t, "ports", "-host", "127.0.0.1", "-p", "55555-55564", "-rate", "5", "-detect", "none", "-ledger", "off", "-json")
	if d < 1800*time.Millisecond {
		t.Errorf("10 connects at -rate 5 took %s, want at least 1.8 s", d)
	}
}
