package contract

import (
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// outcome is what a command of a row said it sent.
type outcome struct{ requests, dns int64 }

// row is one command with one flag set, run against the labs. What it
// sends is seen three ways, and the three must be one: the wire (the
// proxy in front of the site, or the listener of the port), the ledger
// the run wrote, and the requests of its summary.
type row struct {
	name  string
	known string // an open issue this row still breaks, "#N"
	// writes: the row sends a write on purpose, so the GET promise is not asked of it.
	writes bool
	// direct: the row reaches the site without the proxy: the site's own record is the wire.
	direct bool
	// ledgers are the ledger files of the row, relative to the directory.
	ledgers []string
	// exit is the exit code a clean lab gives each command, 0 when empty.
	exit []int
	// do runs the commands and returns what each said it sent.
	do func(l *Labs) []outcome
}

func (l *Labs) sent(rs ...Result) []outcome {
	var out []outcome
	for _, r := range rs {
		out = append(out, outcome{r.Summary.Requests, r.Summary.DNSQueries})
	}
	return out
}

// proxied are the flags that put a run behind the lab's proxy and give it a ledger.
func (l *Labs) proxied(ledger string) []string {
	return []string{"-proxy", l.Proxy.URL, "-ledger", ledger}
}

func rows() []row {
	return []row{
		{name: "probe", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"probe", "-u", l.Site.URL}, l.proxied("l.jsonl")...)...))
		}},
		{name: "probe -path -fr", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"probe", "-u", l.Site.URL, "-path", "/old", "-fr", "-sr"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "crawl", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"crawl", "-u", l.Site.URL, "-d", "3"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "crawl -hints -assets", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"crawl", "-u", l.Site.URL, "-d", "3", "-hints", "-assets"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "crawl -deny-path", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"crawl", "-u", l.Site.URL, "-d", "3", "-deny-path", "^/admin"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "crawl -submit-forms", writes: true, ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"crawl", "-u", l.Site.URL, "-d", "3", "-submit-forms"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "run", ledgers: []string{"w.db.ledger.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-proxy", l.Proxy.URL))
		}},
		{name: "run -passive", ledgers: []string{"w.db.ledger.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-passive", "-db", "w.db", "-proxy", l.Proxy.URL))
		}},
		{name: "run -deny-path -depth 1", ledgers: []string{"w.db.ledger.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-depth", "1", "-deny-path", "^/api", "-db", "w.db", "-proxy", l.Proxy.URL))
		}},
		{name: "run -max-requests then resume", exit: []int{4, 0}, ledgers: []string{"w.db.ledger.jsonl"}, do: func(l *Labs) []outcome {
			a := l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-max-requests", "20", "-db", "w.db", "-proxy", l.Proxy.URL)
			b := l.Cmd("resume", "-db", "w.db", "-max-requests", "0", "-proxy", l.Proxy.URL)
			return l.sent(a, b)
		}},
		{name: "dirs", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			w := l.File("words.txt", "admin\nbackup\nabout\nnope\nold\nrobots.txt\n")
			return l.sent(l.Cmd(append([]string{"dirs", "-u", l.Site.URL, "-w", w}, l.proxied("l.jsonl")...)...))
		}},
		{name: "dirs -ac=false -e", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			w := l.File("words.txt", "admin\nbackup\nnope\n")
			return l.sent(l.Cmd(append([]string{"dirs", "-u", l.Site.URL, "-w", w, "-ac=false", "-e", ".bak"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "fuzz", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			w := l.File("words.txt", "about\nproducts\nnope\n")
			return l.sent(l.Cmd(append([]string{"fuzz", "-u", l.Site.URL + "/FUZZ", "-w", w}, l.proxied("l.jsonl")...)...))
		}},
		{name: "params", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd(append([]string{"params", "-u", l.Site.URL + "/products", "-w", "small"}, l.proxied("l.jsonl")...)...))
		}},
		{name: "roles", ledgers: []string{"rd/roles.ledger.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Cmd("roles", "-role", "anon", "-role", "alice=Authorization: Bearer t-alice", "-role", "bob=Authorization: Bearer t-bob",
				"-replay", "-dir", "rd", "-proxy", l.Proxy.URL, "--", "-url", l.Site.URL, "-allow", l.Allow()))
		}},
		{name: "roles -ledger", known: "", writes: true, ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			h := l.File("alice.har", har(l.Site, [2]string{"GET", "/api/v1/items/1"}, [2]string{"POST", "/api/v1/items"}))
			return l.sent(l.Cmd("roles", "-role", "anon", "-role", "bob=Authorization: Bearer t-bob", "-har", "alice="+h,
				"-replay", "-replay-writes", "post", "-dir", "rd", "-proxy", l.Proxy.URL, "--", "-url", l.Site.URL, "-allow", l.Allow(), "-ledger", "l.jsonl"))
		}},
		{name: "roles -har -replay-writes", writes: true, ledgers: []string{"rd/roles.ledger.jsonl"}, do: func(l *Labs) []outcome {
			h := l.File("alice.har", har(l.Site, [2]string{"GET", "/api/v1/items/1"}, [2]string{"POST", "/api/v1/items"}))
			return l.sent(l.Cmd("roles", "-role", "anon", "-role", "bob=Authorization: Bearer t-bob", "-har", "alice="+h,
				"-replay", "-replay-writes", "post", "-dir", "rd", "-proxy", l.Proxy.URL, "--", "-url", l.Site.URL, "-allow", l.Allow()))
		}},
		{name: "watch twice", ledgers: []string{"w.db.ledger.jsonl"}, do: func(l *Labs) []outcome {
			a := l.Cmd("watch", "-db", "w.db", "--", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-proxy", l.Proxy.URL)
			b := l.Cmd("watch", "-db", "w.db", "--", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-proxy", l.Proxy.URL)
			return l.sent(a, b)
		}},
		{name: "ports", direct: true, ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			l.Ports = newPortLab(l.T)
			return l.sent(l.Cmd("ports", "-host", "127.0.0.1", "-p", l.Ports.List(), "-ledger", "l.jsonl", "-allow", "127.0.0.1"))
		}},
		{name: "ports -detect none", direct: true, ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			l.Ports = newPortLab(l.T)
			return l.sent(l.Cmd("ports", "-host", "127.0.0.1", "-p", l.Ports.List(), "-detect", "none", "-ledger", "l.jsonl", "-allow", "127.0.0.1"))
		}},
		{name: "ports -udp", direct: true, ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			l.Ports = newPortLab(l.T)
			l.UDP = listenUDP(l.T, l.Ports.Wire)
			return l.sent(l.Cmd("ports", "-host", "127.0.0.1", "-p", portOf(l.Ports.Banner), "-pu", portOf(l.UDP), "-ledger", "l.jsonl", "-allow", "127.0.0.1"))
		}},
		{name: "shots", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Chrome("shots", "-u", l.Site.URL, "-dir", "sh", "-proxy", l.Proxy.URL, "-ledger", "l.jsonl"))
		}},
		{name: "crawl -browser", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			return l.sent(l.Chrome("crawl", "-u", l.Site.URL, "-d", "1", "-browser", "-proxy", l.Proxy.URL, "-ledger", "l.jsonl"))
		}},
		{name: "subs -live -w", ledgers: []string{"w.db.ledger.jsonl"}, do: func(l *Labs) []outcome {
			l.Resolver = newResolver(l.T, "lab.test", "www", "api")
			w := l.File("words.txt", "www\napi\nnope\nfoo\n")
			return l.sent(l.Cmd("subs", "-d", "lab.test", "-sources", "none", "-w", w, "-live", "-resolvers", l.Resolver.Addr, "-no-history", "-db", "w.db"))
		}},
		{name: "dns", ledgers: []string{"l.jsonl"}, do: func(l *Labs) []outcome {
			l.Resolver = newResolver(l.T, "lab.test", "www", "api")
			names := l.File("names.txt", "www.lab.test\napi.lab.test\nnope.lab.test\n")
			return l.sent(l.Cmd("dns", "-l", names, "-resolvers", l.Resolver.Addr, "-ledger", "l.jsonl"))
		}},
	}
}

func TestWireIsLedgerIsSummary(t *testing.T) {
	for _, r := range rows() {
		t.Run(r.name, func(t *testing.T) {
			l := newLabs(t)
			outs := r.do(l)
			v := newInv(t, r.known)
			checkRow(t, v, l, r, outs)
			v.Done()
		})
	}
}

func checkRow(t *testing.T, v *Inv, l *Labs, r row, outs []outcome) {
	t.Helper()
	want := r.exit
	if len(want) == 0 {
		want = []int{0}
	}
	var requests, dnsq int64
	for i, o := range outs {
		requests += o.requests
		dnsq += o.dns
		if got := l.results[i].Code; i < len(want) && got != want[i] || i >= len(want) && got != want[len(want)-1] {
			v.Errorf("command %d exits %d, want %d\n%s", i+1, got, want, l.results[i].Stderr)
		}
	}
	var sent Sent
	var dnsLines int64
	for _, f := range r.ledgers {
		lines := readLedger(t, filepath.Join(l.Dir, f))
		s := ledgerSent(lines)
		sent.N += s.N
		sent.HTTP, sent.TCP, sent.UDP = merge(sent.HTTP, s.HTTP), merge(sent.TCP, s.TCP), merge(sent.UDP, s.UDP)
		sent.Probes = merge(sent.Probes, s.Probes)
		for _, ln := range lines {
			if ln.Kind == "dns" {
				dnsLines++
			}
		}
		if res := RunRaw(t, l.Dir, nil, "ledger", "-verify", f); res.Code != 0 {
			v.Errorf("azhaq ledger -verify %s: exit %d", f, res.Code)
		}
	}

	// summary = ledger
	v.Equal("the summaries say requests; the ledger holds lines to targets", requests, int64(sent.N))
	v.Equal("the summaries say dns_queries; the ledger holds DNS lines", dnsq, dnsLines)

	// ledger = wire
	truth := l.Proxy.Wire
	if r.direct {
		truth = l.Site.Wire
	}
	if d := diff("ledger", sent.HTTP, "wire", truth.HTTP()); d != "" {
		v.Errorf("the ledger's HTTP lines and what the proxy saw differ:\n%s", d)
	}
	if !r.direct && len(sent.HTTP) > 0 {
		// The proxy and the site itself saw the same: the harness is right.
		if d := diff("proxy", l.Proxy.Wire.HTTP(), "site", l.Site.Wire.HTTP()); d != "" {
			t.Fatalf("the harness: the proxy and the site disagree:\n%s", d)
		}
	}
	if l.Ports != nil {
		for _, a := range []string{l.Ports.Closing, l.Ports.Banner, l.Ports.Web} {
			v.Equal("connections to "+a+": the ledger's tcp lines, against accepted", int64(sent.TCP[a]), int64(l.Ports.Wire.TCP()[a]))
		}
		if n := sent.TCP[l.Ports.Gone]; n == 0 && l.Ports.goneAsked {
			v.Errorf("the closed port %s has no line in the ledger", l.Ports.Gone)
		}
		v.Equal("the ledger's lines to targets, against the TCP lines", int64(sent.N), int64(sumMap(sent.TCP)+sumMap(sent.HTTP)+sumMap(sent.UDP)))
		// What a logging server in front of the web port counted is listed as probe lines.
		if d := diff("ledger probes", sent.Probes, "asked at the port", l.Ports.Asked.HTTP()); d != "" {
			v.Errorf("the ledger's probe lines and the requests the web port saw differ:\n%s", d)
		}
	}
	if l.UDP != "" {
		v.Equal("packets to "+l.UDP+": the ledger's udp lines, against received", int64(sent.UDP[l.UDP]), int64(l.Ports.Wire.UDP()[l.UDP]))
	}
	if l.Resolver != nil {
		v.Equal("DNS lines of the ledger, against packets the resolver got", dnsLines, int64(l.Resolver.Wire.Total()))
	}
	if !r.writes {
		for k := range sent.HTTP {
			if m, _, _ := strings.Cut(k, " "); !slices.Contains([]string{"GET", "HEAD", "OPTIONS"}, m) {
				v.Errorf("a run without a write flag sent %s", k)
			}
		}
	}
}

func merge(a, b map[string]int) map[string]int {
	if a == nil {
		a = map[string]int{}
	}
	for k, v := range b {
		a[k] += v
	}
	return a
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

var _ = net.JoinHostPort
var _ = fmt.Sprint

// The MCP server is a command too: what each tool says it sent is what
// reached the site and the ports, and a tool that keeps a workspace has the
// ledger of it.
func TestMCPWireIsLedgerIsSummary(t *testing.T) {
	l := newLabs(t)
	l.Ports = newPortLab(t)
	c := startMCP(t, l.Dir, "-allow", "127.0.0.1")
	open := fmt.Sprintf("%s,%s,%s", portOf(l.Ports.Closing), portOf(l.Ports.Banner), portOf(l.Ports.Web))
	for _, call := range []struct {
		tool   string
		args   map[string]any
		ledger string // the workspace ledger the call fills, if any
	}{
		{"azhaq_probe", map[string]any{"targets": []string{l.Site.URL}}, ""},
		{"azhaq_map", map[string]any{"url": l.Site.URL, "workspace": "w"}, "w.db.ledger.jsonl"},
		{"azhaq_ports", map[string]any{"hosts": []string{"127.0.0.1"}, "ports": open}, ""},
	} {
		l.Site.Wire.Reset()
		l.Ports.Wire.Reset()
		s := c.Tool(call.tool, call.args)
		v := newInv(t, "")
		v.Equal(call.tool+": the summary's requests, against what reached the site and the ports", s.Requests, int64(l.Site.Wire.Total()+l.Ports.Wire.Total()))
		if call.ledger != "" {
			sent := ledgerSent(readLedger(t, filepath.Join(l.Dir, "ws", call.ledger)))
			v.Equal(call.tool+": the summary's requests, against the workspace ledger's lines to targets", s.Requests, int64(sent.N))
			if d := diff("ledger", sent.HTTP, "site", l.Site.Wire.HTTP()); d != "" {
				v.Errorf("%s: the ledger and what the site got differ:\n%s", call.tool, d)
			}
		}
		if v.Done(); t.Failed() {
			return
		}
	}
}

// Every request the tools sent is in a ledger of the server: a workspace's,
// or the server's own for the tools with no workspace.
func TestMCPLedgersHoldEveryRequestTheToolsSent(t *testing.T) {
	l := newLabs(t)
	l.Ports = newPortLab(t)
	c := startMCP(t, l.Dir, "-allow", "127.0.0.1")
	var total int64
	total += c.Tool("azhaq_probe", map[string]any{"targets": []string{l.Site.URL}}).Requests
	total += c.Tool("azhaq_map", map[string]any{"url": l.Site.URL, "workspace": "w"}).Requests
	total += c.Tool("azhaq_ports", map[string]any{"hosts": []string{"127.0.0.1"}, "ports": portOf(l.Ports.Banner)}).Requests
	files, _ := filepath.Glob(filepath.Join(l.Dir, "*", "*.ledger.jsonl"))
	var lines int
	for _, f := range files {
		lines += ledgerSent(readLedger(t, f)).N
	}
	v := newInv(t, "")
	v.Equal("the summaries' requests over all tool calls, against the lines to targets of every ledger the server wrote", total, int64(lines))
	v.Done()
}

func portOf(addr string) string { _, p, _ := net.SplitHostPort(addr); return p }
