package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

// ports counts only addresses, which have no answer to tell from a failure,
// so any failure it lists exits 3; a run given a URL that answered, the same
// failure, exits 0.
func TestPortsAnyFailureExitsThree(t *testing.T) {
	fail := []engine.Failure{{Collector: "azhaq-ports", Error: "timeout", Targets: []string{"10.0.0.5"}, Count: 1}}
	seeds := []types.Seed{{Type: types.TypeIPAddress, Keys: map[string]string{"ip": "10.0.0.5"}}, {Type: types.TypePrefix, Keys: map[string]string{"prefix": "10.0.1.0/24"}}}
	rep := newReport("ports")
	rep.Failed = fail
	rep.targets = tallySeeds("ports", seeds, nil, fail)
	if rep.targets.given != 0 || rep.decide() != exitPartial {
		t.Errorf("ports: %d targets counted, exit %d, want none counted and exit 3", rep.targets.given, rep.decide())
	}
	run := newReport("run")
	run.Failed = []engine.Failure{{Collector: "azhaq-http", Error: "timeout", Targets: []string{"http://b.test/x"}, Count: 1}}
	run.targets = tallySeeds("run", []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://a.test/"}}}, nil, run.Failed)
	if run.targets.given != 1 || run.decide() != exitOK {
		t.Errorf("run: %d targets counted, exit %d, want one counted and exit 0", run.targets.given, run.decide())
	}
}

// -sweep takes -eh, -max-requests, -rate and the kill file as any target
// does: the excluded address is not connected to, the cap stops the run with
// work left, the pace spaces the connects, and an existing kill file stops it
// before a connect.
func TestPortsSweepHoldsExcludedHostsTheBudgetThePaceAndTheKillFile(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := newSweepLab(t)
	base := []string{"ports", "-sweep", "-allow", "127.7.7.0/29", "-p", lab.port, "-detect", "none", "-json"}
	out, _, code := cli(t, append(base, "-eh", "127.7.7.6")...)
	if got := portRows(t, out); code != exitOK || fmt.Sprint(got) != "[127.7.7.2 127.7.7.5]" || lab.dialed("127.7.7.6") != 0 {
		t.Errorf("-eh: exit %d, rows %v, .6 dialed %d", code, got, lab.dialed("127.7.7.6"))
	}
	_, errOut, code := cli(t, append(base, "-max-requests", "3")...)
	if rep := lastReport(t, errOut); code != exitLimit || rep.Requests != 3 {
		t.Errorf("-max-requests 3: exit %d, %d requests", code, rep.Requests)
	}
	t0 := time.Now()
	_, _, code = cli(t, append(base, "-rate", "5")...)
	if d := time.Since(t0); code != exitOK || d < 1200*time.Millisecond {
		t.Errorf("-rate 5 over 8 addresses: exit %d in %v, want the connects paced", code, d)
	}
	if err := os.WriteFile("k.stop", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	before := lab.dialed("127.7.7.5")
	_, errOut, code = cli(t, append(base, "-kill-file", "k.stop")...)
	if rep := lastReport(t, errOut); code != exitLimit || rep.Requests != 0 || lab.dialed("127.7.7.5") != before {
		t.Errorf("a kill file that exists: exit %d, %d requests", code, rep.Requests)
	}
}

// zoneOf answers A and AAAA queries from the lists given, on 127.0.0.1, and
// returns a -resolvers value.
func zoneOf(t *testing.T, name string, a, aaaa []string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if strings.TrimSuffix(strings.ToLower(q.Name), ".") == name {
			list, typ := a, "A"
			if q.Qtype == dns.TypeAAAA {
				list, typ = aaaa, "AAAA"
			}
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
				for _, ip := range list {
					rr, _ := dns.NewRR(fmt.Sprintf("%s. 60 IN %s %s", name, typ, ip))
					m.Answer = append(m.Answer, rr)
				}
			}
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// A name's first two IPv4 addresses are scanned; -sa scans every address, -iv 4
// keeps IPv4 and -iv 6 leaves IPv4 alone.
func TestPortsSAndIVChooseWhichAddressesOfANameAreScanned(t *testing.T) {
	t.Chdir(t.TempDir())
	var dials atomic.Int32
	var v4 []string
	port := ""
	for i, ip := range []string{"127.8.0.1", "127.8.0.2", "127.8.0.3"} {
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
		v4 = append(v4, ip)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				dials.Add(1)
				c.Close()
			}
		}()
	}
	res := zoneOf(t, "multi.test", v4, nil)
	base := []string{"ports", "-host", "multi.test", "-p", port, "-detect", "none", "-json", "-resolvers", res, "-allow", "multi.test", "-allow", "127.0.0.0/8"}
	ips := func(extra ...string) []string {
		out, errOut, code := cli(t, append(slices.Clone(base), extra...)...)
		if code != exitOK {
			t.Fatalf("%v: exit %d\n%s", extra, code, errOut)
		}
		return portRows(t, out)
	}
	if got := ips(); fmt.Sprint(got) != "[127.8.0.1 127.8.0.2]" {
		t.Errorf("by default %v: the first two addresses", got)
	}
	if got := ips("-sa"); fmt.Sprint(got) != "[127.8.0.1 127.8.0.2 127.8.0.3]" {
		t.Errorf("-sa %v: every address", got)
	}
	if got := ips("-iv", "4"); fmt.Sprint(got) != "[127.8.0.1 127.8.0.2]" {
		t.Errorf("-iv 4 %v", got)
	}
	time.Sleep(200 * time.Millisecond) // the connects of the runs above are counted by now
	before := dials.Load()
	got := ips("-iv", "6")
	time.Sleep(200 * time.Millisecond)
	if len(got) != 0 || dials.Load() != before {
		t.Errorf("-iv 6 %v, %d IPv4 connects: no IPv4 address is scanned", got, dials.Load()-before)
	}
}

// -rate is a ceiling: 1,500 ports on the loopback are spaced over about
// three seconds at -rate 500. -min-rate sizes nothing: it keeps every core.
func TestPortsRateIsACeilingAndMinRateKeepsEveryCore(t *testing.T) {
	t.Chdir(t.TempDir())
	args := []string{"ports", "-host", "127.0.0.1", "-p", "1-1500", "-detect", "none", "-silent", "-ledger", "off"}
	was := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(was) })
	cli(t, append(slices.Clone(args), "-min-rate", "5000")...)
	if got := runtime.GOMAXPROCS(0); got != was && os.Getenv("GOMAXPROCS") == "" {
		t.Errorf("-min-rate left GOMAXPROCS at %d, was %d: it keeps every core", got, was)
	}
	t0 := time.Now()
	cli(t, append(slices.Clone(args), "-rate", "500")...)
	if d := time.Since(t0); d < 2500*time.Millisecond {
		t.Errorf("-rate 500 took %v for 1,500 ports: a ceiling spaces them over about 3 s", d)
	}
}

// A scan through -proxy or from -source-ip asks each open port its banner
// only (the service probes beyond the first connection dial on their own),
// and the summary says so; -proxy with UDP is refused.
func TestPortsProxyAndSourceIPAskTheBannerOnlyAndSayIt(t *testing.T) {
	t.Chdir(t.TempDir())
	var accepted atomic.Int32
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			t.Cleanup(func() { c.Close() }) // silent until the test ends
		}
	}()
	port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
	asked := func(extra ...string) (int32, string) {
		accepted.Store(0)
		_, errOut, code := cli(t, append([]string{"ports", "-host", "127.0.0.1", "-p", port, "-json", "-connect-timeout", "200", "-ledger", "off"}, extra...)...)
		if code != exitOK {
			t.Fatalf("%v: exit %d\n%s", extra, code, errOut)
		}
		time.Sleep(300 * time.Millisecond)
		return accepted.Load(), strings.Join(lastReport(t, errOut).Notes, "\n")
	}
	if n, notes := asked(); n < 2 || strings.Contains(notes, "banner only") {
		t.Errorf("by default a silent port was connected to %d times, notes %q: want it asked more than once", n, notes)
	}
	if n, notes := asked("-source-ip", "127.0.0.1"); n != 1 || !strings.Contains(notes, "-source-ip: each port is asked its banner only") {
		t.Errorf("-source-ip: %d connects, notes %q", n, notes)
	}
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-udp", "-proxy", "127.0.0.1:1", "-json")
	if code != exitUsage || !strings.Contains(errOut, "-proxy carries TCP only: leave out -udp and -pu") {
		t.Errorf("-proxy with -udp: exit %d\n%s", code, errOut)
	}
	_, errOut, code = cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-proxy", "127.0.0.1:1", "-json", "-connect-timeout", "200", "-ledger", "off")
	if notes := strings.Join(lastReport(t, errOut).Notes, "\n"); !strings.Contains(notes, "-proxy: each port is asked its banner only (-detect banner)") {
		t.Errorf("-proxy: exit %d, notes %q", code, notes)
	}
}

// The nmap XML and greppable files list each silent UDP port as nmap does,
// with -udp-rows or without it, while the output has one row for them without.
func TestPortsNmapFilesListEachSilentUDPPortWithOrWithoutUDPRows(t *testing.T) {
	t.Chdir(t.TempDir())
	var ports []string
	for i := 0; i < 3; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 64)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		ports = append(ports, fmt.Sprint(pc.LocalAddr().(*net.UDPAddr).Port))
	}
	for _, rows := range []bool{false, true} {
		args := []string{"ports", "-host", "127.0.0.1", "-p", "none", "-pu", strings.Join(ports, ","), "-connect-timeout", "200ms", "-json", "-oX", "scan.xml", "-oG", "scan.gnmap"}
		if rows {
			args = append(args, "-udp-rows")
		}
		out, _, code := cli(t, args...)
		xml, _ := os.ReadFile("scan.xml")
		gnmap, _ := os.ReadFile("scan.gnmap")
		for _, p := range ports {
			if !strings.Contains(string(xml), `portid="`+p+`"`) || !strings.Contains(string(gnmap), p+"/open|filtered/udp") {
				t.Errorf("-udp-rows %v: port %s is not in the nmap files:\n%s\n%s", rows, p, xml, gnmap)
			}
		}
		if want := map[bool]int{false: 1, true: 3}[rows]; code != exitOK || len(lines(out)) != want {
			t.Errorf("-udp-rows %v: exit %d, %d rows printed, want %d", rows, code, len(lines(out)), want)
		}
	}
}
