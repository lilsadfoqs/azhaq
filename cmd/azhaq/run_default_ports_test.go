package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	_ "modernc.org/sqlite"
)

// webOn serves HTTP on ip:port (port 0: any free one) until the test ends, and
// returns the port; a port that is taken here skips the test.
func webOn(t *testing.T, ip string, port int) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		t.Skipf("no %s:%d: %v", ip, port, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// answersOn are the ports of list that accept a connect on ip: what the first pass
// of a scan of ip finds, asked by the test itself.
func answersOn(ip string, list []int) []int {
	var open []int
	for _, p := range list {
		if c, err := net.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(p))); err == nil {
			c.Close()
			open = append(open, p)
		}
	}
	return open
}

// portRowsOf reads the finished port rows of a workspace by address: how many ports
// each was asked and which were open.
func portRowsOf(t *testing.T, db string) (scanned map[string]int, open map[string][]int) {
	t.Helper()
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT payload FROM observations WHERE collector = 'azhaq-ports' AND kind = 'ports' ORDER BY observed_at, rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	scanned, open = map[string]int{}, map[string][]int{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var row struct {
			IP       string `json:"ip"`
			Scanned  int    `json:"scanned"`
			Partial  bool   `json:"partial"`
			Range    bool   `json:"range"`
			Services []struct {
				Port int `json:"port"`
			} `json:"services"`
		}
		if json.Unmarshal([]byte(payload), &row) != nil || row.IP == "" || row.Range {
			continue
		}
		if row.Partial {
			delete(scanned, row.IP) // a whole scan came after it, or the scan is not whole
			delete(open, row.IP)
			continue
		}
		scanned[row.IP] = row.Scanned
		open[row.IP] = nil
		for _, s := range row.Services {
			open[row.IP] = append(open[row.IP], s.Port)
		}
	}
	return scanned, open
}

// connectsByAddress reads, from the ledger of a run, the distinct ports each address
// was connected to by the port scan.
func connectsByAddress(t *testing.T, path string) map[string]map[int]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]map[int]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e struct{ Kind, Target, Collector string }
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Kind != "tcp" || e.Collector != "azhaq-ports" {
			continue
		}
		host, port, err := net.SplitHostPort(e.Target)
		if err != nil {
			continue
		}
		if n, err := strconv.Atoi(port); err == nil {
			if out[host] == nil {
				out[host] = map[int]bool{}
			}
			out[host][n] = true
		}
	}
	return out
}

// A range with no -ports is asked the top 1000 ports (and the usual ports of the
// services azhaq names) of every address, then every port of each address that
// answered, and of those alone. The services here sit outside the old default of
// 163 ports, some outside the top 1000 as well; each address answers on one port
// of the first pass, so the second finds the rest.
func TestRunDefaultPortsAsksEveryPortOfTheAddressesThatAnswered(t *testing.T) {
	first := portscan.DefaultPorts()
	top, _ := portscan.Ports("top-1000")
	usual := portscan.UsualPorts()
	// The ports of the first pass something answers on everywhere here (a wildcard listener) are
	// left out of the scan, so that an address with no service of the test's answers nothing.
	skip := answersOn("127.55.9.3", first)
	asked := len(first) - len(skip)
	skipFlag := []string{}
	if len(skip) > 0 {
		skipFlag = []string{"-port-skip", portscan.Compact(skip)}
	}

	// One port of the first pass that the old default did not ask starts each address's answer.
	var trigger []int
	for _, p := range top {
		if !slices.Contains(usual, p) && !slices.Contains(skip, p) && p > 1024 {
			trigger = append(trigger, p)
		}
	}
	if len(trigger) < 2 {
		t.Fatal("the top 1000 holds nothing the usual set lacks")
	}
	want := map[string][]int{
		"127.55.9.1": {webOn(t, "127.55.9.1", trigger[0]), webOn(t, "127.55.9.1", 5984), webOn(t, "127.55.9.1", 50070), webOn(t, "127.55.9.1", 0)},
		"127.55.9.2": {webOn(t, "127.55.9.2", trigger[1]), webOn(t, "127.55.9.2", 8161), webOn(t, "127.55.9.2", 11211), webOn(t, "127.55.9.2", 27017)},
	}
	t.Chdir(t.TempDir())
	args := append([]string{"run", "-cidr", "127.55.9.0/30", "-allow", "127.55.9.0/30", "-sources", "none", "-no-paths", "-no-favicon", "-no-tech",
		"-port-detect", "none", "-db", "d.db"}, skipFlag...)
	_, rep, code := runContract(t, args...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	scanned, open := portRowsOf(t, "d.db")
	for ip, ports := range want {
		for _, p := range ports {
			if !slices.Contains(open[ip], p) {
				t.Errorf("%s:%d was not found; open ports %v", ip, p, open[ip])
			}
		}
		if scanned[ip] != 65535-len(skip) {
			t.Errorf("%s was asked %d ports, want every one of the 65535 but those skipped", ip, scanned[ip])
		}
	}
	// The addresses that answered nothing were asked the first pass and no more.
	ledger := connectsByAddress(t, "d.db.ledger.jsonl")
	for _, ip := range []string{"127.55.9.0", "127.55.9.3"} {
		if scanned[ip] != 0 && scanned[ip] != asked {
			t.Errorf("%s answered nothing and was asked %d ports, want the %d of the first pass", ip, scanned[ip], asked)
		}
		for p := range ledger[ip] {
			if !slices.Contains(first, p) {
				t.Errorf("%s answered nothing, and port %d, outside the first pass, was asked of it", ip, p)
				break
			}
		}
	}
	for ip := range want {
		if n := len(ledger[ip]); n < 65000 {
			t.Errorf("%s answered and was connected to on %d ports, want almost every one of 65535", ip, n)
		}
	}
	if rep.AddressesScanned == nil || *rep.AddressesScanned != 4 || rep.AddressesOpen == nil || *rep.AddressesOpen != 2 {
		t.Errorf("addresses scanned %v, with an open port %v: want 4 and 2", rep.AddressesScanned, rep.AddressesOpen)
	}
	// What was left is named: the two addresses that answered nothing had no second pass.
	next := strings.Join(rep.Next, "\n")
	if !strings.Contains(next, fmt.Sprintf("were not asked on 2 addresses: %d connects", (65535-asked)*2)) {
		t.Errorf("the next pass does not name the 2 addresses that answered nothing:\n%s", next)
	}
}

// planOf is a plan's lines on what it sends and its ports stage.
func planOf(t *testing.T, args ...string) (sends []string, ports map[string]any) {
	t.Helper()
	out, _, _ := cli(t, append(append([]string{"plan"}, args...), "-sources", "none", "-json")...)
	var p struct {
		Sends    []string `json:"sends"`
		Estimate struct {
			Stages []map[string]any `json:"stages"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, st := range p.Estimate.Stages {
		if st["stage"] == "ports" {
			ports = st
		}
	}
	return p.Sends, ports
}

func hasLine(lines []string, parts ...string) bool {
	for _, l := range lines {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return true
		}
	}
	return false
}

// The plan and the cost estimate show both passes before anything is sent: the
// first pass of every address is the floor of a range, the second is named with
// what it adds on each address that answers, and the ceiling counts every port.
func TestPlanShowsBothPassesOfTheDefaultScan(t *testing.T) {
	first := len(portscan.DefaultPorts())
	rest := 65535 - first
	for _, extra := range [][]string{nil, {"-ports", "default"}} {
		args := append([]string{"-cidr", "127.55.9.0/30", "-allow", "127.55.9.0/30"}, extra...)
		sends, ports := planOf(t, args...)
		if !hasLine(sends, "TCP connects", fmt.Sprintf("to %d ports of each address", first)) {
			t.Errorf("%v: the plan does not name the first pass of %d ports: %q", extra, first, sends)
		}
		if !hasLine(sends, "pass 2", fmt.Sprintf("the other %d of the 65535 TCP ports of each address that answered pass 1", rest)) {
			t.Errorf("%v: the plan does not name the second pass of %d ports: %q", extra, rest, sends)
		}
		if got := stageAmount(ports, "estimate", "connects"); got != float64(4*first) {
			t.Errorf("%v: the estimate is %v connects, want %d (the first pass of 4 addresses)", extra, got, 4*first)
		}
		if note, _ := ports["not_counted"].(string); !strings.Contains(note, fmt.Sprintf("pass 2 of -ports default on each address of a range that answers pass 1 (%d connects each)", rest)) {
			t.Errorf("%v: the estimate does not say what pass 2 adds: %q", extra, note)
		}
		if most, _ := ports["at_most"].(float64); most < 4*65535 {
			t.Errorf("%v: the ceiling is %v, below every port of 4 addresses", extra, most)
		}
	}
	// An address given alone is taken to answer: both passes are in the floor.
	if _, ports := planOf(t, "-cidr", "127.55.9.1/32", "-allow", "127.55.9.1"); stageAmount(ports, "estimate", "connects") != 65535 {
		t.Errorf("one address: the estimate is %v connects, want 65535", stageAmount(ports, "estimate", "connects"))
	}
	// The sets named keep their meaning, and a name or a URL alone starts no scan.
	sends, ports := planOf(t, "-cidr", "127.55.9.0/30", "-allow", "127.55.9.0/30", "-ports", "top-100")
	if stageAmount(ports, "estimate", "connects") != 400 || hasLine(sends, "pass 2") {
		t.Errorf("-ports top-100: estimate %v, sends %q", ports, sends)
	}
	if sends, ports = planOf(t, "-cidr", "127.55.9.0/30", "-allow", "127.55.9.0/30", "-ports", "none"); stageAmount(ports, "estimate", "connects") != 0 || hasLine(sends, "TCP connects") {
		t.Errorf("-ports none: %v, %q", ports, sends)
	}
	if sends, ports = planOf(t, "-url", "http://127.55.9.1:8000/", "-allow", "127.55.9.1"); stageAmount(ports, "estimate", "connects") != 0 || hasLine(sends, "TCP connects") {
		t.Errorf("a URL alone: %v, %q", ports, sends)
	}
	if sends, ports = planOf(t, "-domain", "example.test", "-allow", "example.test"); stageAmount(ports, "estimate", "connects") != 0 || hasLine(sends, "TCP connects") {
		t.Errorf("a domain alone: %v, %q", ports, sends)
	}
	// The text says it too.
	out, _, _ := cli(t, "plan", "-cidr", "127.55.9.0/30", "-allow", "127.55.9.0/30", "-sources", "none")
	if !strings.Contains(out, "then, in pass 2, TCP connects to the other") {
		t.Errorf("the plan's text does not name pass 2:\n%s", out)
	}
}

// -max-requests cuts a pass: the summary names the pass, the addresses and the
// ports left, and the run exits 4; azhaq resume asks what is left and ends 0.
func TestRunDefaultPortsBudgetCutsPassTwoAndResumeFinishesIt(t *testing.T) {
	first := portscan.DefaultPorts()
	skip := answersOn("127.55.9.3", first)
	skipFlag := []string{}
	if len(skip) > 0 {
		skipFlag = []string{"-port-skip", portscan.Compact(skip)}
	}
	asked := len(first) - len(skip)
	top, _ := portscan.Ports("top-1000")
	usual := portscan.UsualPorts()
	var trigger []int
	for _, p := range top {
		if !slices.Contains(usual, p) && !slices.Contains(skip, p) && p > 1024 {
			trigger = append(trigger, p)
		}
	}
	want := map[string][]int{
		"127.55.9.1": {webOn(t, "127.55.9.1", trigger[0]), webOn(t, "127.55.9.1", 50070)},
		"127.55.9.2": {webOn(t, "127.55.9.2", trigger[1]), webOn(t, "127.55.9.2", 8161)},
	}
	t.Chdir(t.TempDir())
	base := []string{"run", "-cidr", "127.55.9.0/30", "-allow", "127.55.9.0/30", "-sources", "none", "-no-paths", "-no-favicon", "-no-tech", "-port-detect", "none", "-db", "d.db"}
	// Room for the first pass of the 4 addresses and a part of the second.
	_, rep, code := runContract(t, append(append(slices.Clone(base), skipFlag...), "-max-requests", strconv.Itoa(4*asked+20000))...)
	if code != exitLimit {
		t.Fatalf("exit %d, want %d (a limit stopped it): stopped %q failed %+v", code, exitLimit, rep.Stopped, rep.Failed)
	}
	if !strings.Contains(rep.Stopped, "pass 2 of 2") || strings.Contains(rep.Stopped, "pass 1 of 2") || !strings.Contains(rep.Stopped, "2 addresses with ports left") {
		t.Errorf("stopped does not name pass 2 and the 2 addresses that answered: %q", rep.Stopped)
	}
	if rep.Requests > int64(4*asked+20000) {
		t.Errorf("%d requests sent, over the limit", rep.Requests)
	}
	// The addresses that answered nothing had the whole first pass, and have no row: the range's counts them.
	ledger := connectsByAddress(t, "d.db.ledger.jsonl")
	for _, ip := range []string{"127.55.9.0", "127.55.9.3"} {
		if len(ledger[ip]) != asked {
			t.Errorf("%s was connected to on %d ports before the limit, want the %d of the first pass", ip, len(ledger[ip]), asked)
		}
	}
	// The rest, with no limit.
	_, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", "d.db", "-max-requests", "0", "-json"}) })
	if exitCode(err) != exitOK {
		t.Fatalf("resume exit %d: %s", exitCode(err), errOut)
	}
	scanned, open := portRowsOf(t, "d.db")
	for ip, ports := range want {
		if scanned[ip] != 65535-len(skip) {
			t.Errorf("%s was asked %d ports after the resume, want %d", ip, scanned[ip], 65535-len(skip))
		}
		for _, p := range ports {
			if !slices.Contains(open[ip], p) {
				t.Errorf("%s:%d not found after the resume: %v", ip, p, open[ip])
			}
		}
	}
	// A limit inside the first pass is named as that.
	t.Chdir(t.TempDir())
	_, rep, code = runContract(t, append(append(slices.Clone(base), skipFlag...), "-max-requests", "700")...)
	if code != exitLimit || !strings.Contains(rep.Stopped, "pass 1 of 2") || strings.Contains(rep.Stopped, "pass 2 of 2") {
		t.Errorf("exit %d, stopped %q: want pass 1 named", code, rep.Stopped)
	}
}

// ports follows the default: with no -p, or -p default, a host that answered the
// first pass is asked every port, and -ep leaves ports out of both passes.
func TestPortsDefaultGoesOnToEveryPortOfAHostThatAnswered(t *testing.T) {
	first := portscan.DefaultPorts()
	skip := answersOn("127.55.9.3", first)
	top, _ := portscan.Ports("top-1000")
	usual := portscan.UsualPorts()
	trigger := 0
	for _, p := range top {
		if !slices.Contains(usual, p) && !slices.Contains(skip, p) && p > 1024 {
			trigger = p
			break
		}
	}
	high := webOn(t, "127.55.9.1", 50070)
	webOn(t, "127.55.9.1", trigger)
	webOn(t, "127.55.9.2", 50071) // answers nothing in the first pass: no second pass
	for _, spec := range [][]string{nil, {"-p", "default"}} {
		t.Chdir(t.TempDir())
		args := append([]string{"ports", "-host", "127.55.9.1,127.55.9.2,127.55.9.3", "-detect", "none", "-db", "p.db", "-json"}, spec...)
		if len(skip) > 0 {
			args = append(args, "-ep", portscan.Compact(skip))
		}
		out, errOut, code := cli(t, args...)
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		if !strings.Contains(out, `"port":`+strconv.Itoa(high)) || !strings.Contains(out, `"port":`+strconv.Itoa(trigger)) {
			t.Errorf("%v: ports %d and %d of 127.55.9.1 are not both found:\n%s", spec, trigger, high, out)
		}
		if strings.Contains(out, `"port":50071`) {
			t.Errorf("%v: 127.55.9.2 answered nothing in the first pass, and its port 50071 was found:\n%s", spec, out)
		}
		ledger := connectsByAddress(t, "p.db.ledger.jsonl")
		if n := len(ledger["127.55.9.1"]); n < 65000 {
			t.Errorf("%v: the host that answered was connected to on %d ports, want almost every one", spec, n)
		}
		for _, ip := range []string{"127.55.9.2", "127.55.9.3"} {
			if n := len(ledger[ip]); n != len(first)-len(skip) {
				t.Errorf("%v: %s answered nothing and was connected to on %d ports, want the %d of the first pass", spec, ip, n, len(first)-len(skip))
			}
		}
	}
	// A host given with its port is asked that port only, and has no second pass.
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "ports", "-host", "127.55.9.1:"+strconv.Itoa(trigger), "-detect", "none", "-db", "h.db", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if ledger := connectsByAddress(t, "h.db.ledger.jsonl"); len(ledger["127.55.9.1"]) != 1 || !ledger["127.55.9.1"][trigger] {
		t.Errorf("host:port was connected to on %v, want that port only", ledger["127.55.9.1"])
	}
}

// A URL target with an address and a port is an answer of that address: its port
// is asked in the first pass, so an address whose only listener is outside the
// first pass still goes on to the second, and the other ports it serves are found.
func TestRunDefaultPortsCountsTheURLTargetOfAnAddressAsAnswer(t *testing.T) {
	first := portscan.DefaultPorts()
	skip := answersOn("127.55.9.3", first)
	skipFlag := []string{}
	if len(skip) > 0 {
		skipFlag = []string{"-port-skip", portscan.Compact(skip)}
	}
	var port int
	for p := 50070; ; p++ {
		if !slices.Contains(first, p) {
			if ln, err := net.Listen("tcp", "127.55.9.1:"+strconv.Itoa(p)); err == nil {
				ln.Close()
				port = p
				break
			}
		}
	}
	webOn(t, "127.55.9.1", port)
	other := webOn(t, "127.55.9.1", port+1)
	t.Chdir(t.TempDir())
	args := append([]string{"run", "-cidr", "127.55.9.0/30", "-url", "http://127.55.9.1:" + strconv.Itoa(port) + "/", "-allow", "127.55.9.0/30", "-sources", "none",
		"-no-paths", "-no-favicon", "-no-tech", "-port-detect", "none", "-db", "u.db"}, skipFlag...)
	if _, rep, code := runContract(t, args...); code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	scanned, open := portRowsOf(t, "u.db")
	if !slices.Contains(open["127.55.9.1"], other) || !slices.Contains(open["127.55.9.1"], port) {
		t.Errorf("ports %d and %d of the address were not both found: %v", port, other, open["127.55.9.1"])
	}
	if scanned["127.55.9.1"] != 65535-len(skip) {
		t.Errorf("the address was asked %d ports, want %d", scanned["127.55.9.1"], 65535-len(skip))
	}
}
