package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// publicDefaults are the resolvers a run asks without -resolvers. Tests deny
// them, so that a regression cannot send a query there.
const publicDefaults = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112"

// ptrStub is a DNS server that records the questions it is asked and answers
// a PTR with a name.
type ptrStub struct {
	addr string
	mu   sync.Mutex
	qs   []string
	a    map[string]string // name → address, for an A question
}

func newPTRStub(t *testing.T) *ptrStub {
	t.Helper()
	s := &ptrStub{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		s.mu.Lock()
		s.qs = append(s.qs, dns.TypeToString[q.Qtype]+" "+strings.ToLower(q.Name))
		s.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		if q.Qtype == dns.TypePTR {
			m.Answer = append(m.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "host.lab.test."})
		}
		if v, ok := s.a[strings.TrimSuffix(strings.ToLower(q.Name), ".")]; ok && q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Name + " 60 IN A " + v)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	s.addr = pc.LocalAddr().String()
	return s
}

// asSystem makes the stub the system's resolver for the test, and returns it.
func (s *ptrStub) asSystem(t *testing.T) *ptrStub {
	t.Helper()
	restore := egress.SetSystemResolver(&net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", s.addr)
	}})
	t.Cleanup(restore)
	return s
}

func (s *ptrStub) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.qs...)
}

func ptrTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<title>x</title>")) }))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u.Port()
}

func runRange(t *testing.T, port string, extra ...string) (string, map[string]any) {
	t.Helper()
	dir := t.TempDir()
	args := append([]string{"run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1/32", "-sources", "none", "-ports", port, "-no-paths", "-no-tech",
		"-db", dir + "/s.db", "-json"}, extra...)
	_, errOut, _ := cli(t, args...)
	return errOut, sumMap(t, errOut)
}

// With -resolvers the user named the resolver: it is asked the reverse name
// of each address that answers, a loopback one included.
func TestNamedResolversAreAskedForReverseNamesOfLocalAddresses(t *testing.T) {
	t.Chdir(t.TempDir())
	stub := newPTRStub(t)
	_, sum := runRange(t, ptrTarget(t), "-resolvers", stub.addr, "-ledger", "off")
	if got := stub.asked(); len(got) == 0 || got[0] != "PTR 1.0.0.127.in-addr.arpa." {
		t.Fatalf("the named resolver was asked %q, want PTR 1.0.0.127.in-addr.arpa.", got)
	}
	for _, n := range noteList(sum) {
		if strings.Contains(n, "reverse lookup") {
			t.Errorf("a lookup the user named the resolver for is reported held: %s", n)
		}
	}
}

// Without -resolvers the reverse name of a loopback, private or link-local
// address is not sent to the default public resolvers: it is asked of the
// system's resolver (a stub here), the summary counts the lookups and what
// the system answered, and the ledger has a system line and no public one.
// The default resolvers are denied, so a regression sends nothing off this
// machine.
func TestDefaultResolversAreNotAskedForReverseNamesOfLocalAddresses(t *testing.T) {
	t.Chdir(t.TempDir())
	newPTRStub(t).asSystem(t) // 127.0.0.1 is answered from /etc/hosts, as the system does
	led := t.TempDir() + "/l.ledger"
	_, sum := runRange(t, ptrTarget(t), "-deny", publicDefaults, "-ledger", led)
	var held string
	for _, n := range noteList(sum) {
		if strings.Contains(n, "reverse lookup") {
			held = n
		}
	}
	if !strings.HasPrefix(held, "1 reverse lookup (1.0.0.127.in-addr.arpa)") || !strings.Contains(held, "asked of the system's resolver instead: it answered 1;") || !strings.Contains(held, "-resolvers") {
		t.Errorf("the summary does not say the lookup went to the system's resolver, and why: %q", noteList(sum))
	}
	b, err := os.ReadFile(led)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "in-addr.arpa") || !strings.Contains(string(b), `"target":"system"`) || !strings.Contains(string(b), `"method":"PTR"`) {
		t.Errorf("the ledger should have a system PTR line and no reverse name sent to a public resolver:\n%s", b)
	}
}

// dns -ptr of a private address is asked of the system's resolver the same
// way, and the row names it as the resolver that answered.
func TestDNSPTROfAPrivateAddressGoesToTheSystemResolver(t *testing.T) {
	t.Chdir(t.TempDir())
	sys := newPTRStub(t).asSystem(t)
	out, rep, code := dnsOut(t, "-ptr", "-l", writeList(t, "192.168.1.5", "100.64.0.9", "fd00::7"), "-deny", publicDefaults, "-ledger", "off", "-json", "-resp")
	if code != 0 && code != exitPartial {
		t.Logf("exit %d", code)
	}
	rows := dnsRows(t, out)
	if len(rows) != 3 {
		t.Fatalf("%d rows: %v", len(rows), out)
	}
	for h, row := range rows {
		if r, _ := row["resolver"].([]any); len(r) != 1 || r[0] != "system" {
			t.Errorf("%s: resolver %v, want the system's", h, row["resolver"])
		}
	}
	if len(sys.asked()) != 3 {
		t.Errorf("the system's resolver was asked %q", sys.asked())
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "3 reverse lookups") || !strings.Contains(strings.Join(rep.Notes, "\n"), "it answered 3;") {
		t.Errorf("notes %q", rep.Notes)
	}
	// With the resolver named it is asked, and the system's is not.
	stub := newPTRStub(t)
	before := len(sys.asked())
	_, _, _ = dnsOut(t, "-ptr", "-d", "192.168.1.5", "-r", stub.addr, "-silent")
	if got := stub.asked(); len(got) != 1 || got[0] != "PTR 5.1.168.192.in-addr.arpa." || len(sys.asked()) != before {
		t.Errorf("the named resolver was asked %q, the system's %d more times", got, len(sys.asked())-before)
	}
}

func noteList(sum map[string]any) []string {
	var out []string
	ns, _ := sum["notes"].([]any)
	for _, n := range ns {
		s, _ := n.(string)
		out = append(out, s)
	}
	return out
}

// plan names the resolvers a run asks and says that reverse names are among
// the queries, and which of them the default resolvers are not given.
func TestPlanNamesTheResolversAndTheReverseQueries(t *testing.T) {
	line := func(args ...string) string {
		t.Helper()
		out, errOut, code := cli(t, append([]string{"plan", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1/32", "-sources", "none", "-ports", "9"}, args...)...)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		for _, l := range strings.Split(out+errOut, "\n") {
			if strings.HasPrefix(l, "sends: DNS queries to ") {
				return l
			}
		}
		t.Fatalf("no DNS line in the plan:\n%s", out+errOut)
		return ""
	}
	def := line()
	for _, want := range []string{"the default public resolvers (1.1.1.1, ", "reverse names (PTR)", "loopback, private", "kept off the default resolvers and asked of the system's resolver instead", "-resolvers"} {
		if !strings.Contains(def, want) {
			t.Errorf("the plan's DNS line lacks %q: %s", want, def)
		}
	}
	named := line("-resolvers", "127.0.0.1:5301")
	if !strings.Contains(named, "the resolvers given (127.0.0.1:5301)") || !strings.Contains(named, "reverse names (PTR)") || strings.Contains(named, "kept off the default") {
		t.Errorf("with -resolvers: %s", named)
	}
}

// probe -asn asks RIPEstat about public addresses only: a shared-space
// (100.64.0.0/10) or unique-local address is not sent (the guard answers
// before any request, so this test sends nothing).
func TestProbeASNLeavesLocalAddressesOutOfRIPEstat(t *testing.T) {
	p := &probeOut{}
	for _, ip := range []string{"100.64.1.1", "10.0.0.1", "127.0.0.1", "169.254.1.1", "fd00::1", "fe80::1"} {
		if p.asn(ip) != nil {
			t.Errorf("%s was looked up", ip)
		}
	}
}
