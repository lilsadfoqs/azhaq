package dnsr

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

func TestHeldZone(t *testing.T) {
	for name, want := range map[string]bool{
		"app.internal":           true,
		"a.b.INTERNAL.":          true,
		"printer.home.arpa":      true,
		"home.arpa":              true,
		"nas.lan":                true,
		"dc01.corp":              true,
		"wiki.intranet":          true,
		"x.private":              true,
		"x.home":                 true,
		"intranet":               true, // a single label is no delegated TLD either
		"x.onion":                true,
		"app.example.com":        false,
		"com":                    false,
		"app.web":                false, // delegated in the root zone, absent from the public suffix list
		"nic.xn--p1ai":           false,
		"пример.рф":              false,
		"example.arpa":           false,
		"1.0.0.127.in-addr.arpa": false, // LocalReverse's
		"10.in-addr.arpa":        false,
		"127.0.0.1":              false,
		"::1":                    false,
		"":                       false,
		".":                      false,
	} {
		if got := HeldZone(name); got != want {
			t.Errorf("HeldZone(%q) = %v, want %v", name, got, want)
		}
	}
}

func askedNames(asked *[]string) []string {
	var out []string
	for _, a := range *asked {
		out = append(out, strings.Fields(a)[1])
	}
	return out
}

// fakeSystem is the system's resolver replaced by a DNS server on loopback
// (egress.SetSystemResolver: what SystemLookup and SystemReverse ask): it
// records the questions and answers A and PTR from its tables.
type fakeSystem struct {
	mu    sync.Mutex
	asked []string          // "A name", "PTR name"
	names map[string]string // address of an A record by name, or the PTR name by address
}

func (f *fakeSystem) count(qtype string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.asked {
		if strings.HasPrefix(a, qtype+" ") {
			n++
		}
	}
	return n
}

func (f *fakeSystem) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.asked {
		if strings.HasSuffix(a, " "+name) {
			return true
		}
	}
	return false
}

// startSystem makes names the system resolver's records: "host" → "A address"
// is given as host: address, and address → PTR name as address: name.
func startSystem(t *testing.T, names map[string]string) *fakeSystem {
	t.Helper()
	f := &fakeSystem{names: names}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		m := new(dns.Msg)
		m.SetReply(r)
		switch q.Qtype {
		case dns.TypeA:
			f.mu.Lock()
			f.asked = append(f.asked, "A "+name)
			f.mu.Unlock()
			if v, ok := f.names[name]; ok && net.ParseIP(v) != nil {
				rr, _ := dns.NewRR(q.Name + " 60 IN A " + v)
				m.Answer = append(m.Answer, rr)
			} else if !ok {
				m.Rcode = dns.RcodeNameError
			}
		case dns.TypeAAAA:
			if _, ok := f.names[name]; !ok {
				m.Rcode = dns.RcodeNameError
			}
		case dns.TypePTR:
			f.mu.Lock()
			f.asked = append(f.asked, "PTR "+name)
			f.mu.Unlock()
			var ptr string
			for ip, n := range f.names {
				if rev, err := dns.ReverseAddr(ip); err == nil && strings.EqualFold(rev, q.Name) {
					ptr = n
				}
			}
			if ptr == "" {
				m.Rcode = dns.RcodeNameError
			} else {
				rr, _ := dns.NewRR(q.Name + " 60 IN PTR " + ptr)
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	restore := egress.SetSystemResolver(&net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}})
	t.Cleanup(func() { restore(); _ = srv.Shutdown() })
	return f
}

// The default pool does not send a name in an undelegated zone to the
// default resolvers, by any door (Resolve, Query, Lookup): the system's
// resolver is asked for its addresses, and the pool counts the names and the
// answers. A delegated TLD goes out as before.
func TestDefaultPoolAsksTheSystemForNamesInUndelegatedZones(t *testing.T) {
	sys := startSystem(t, map[string]string{"app.corp.internal": "10.1.2.3", "printer.home.arpa": "192.168.1.9", "nas.lan": "10.0.0.7"})
	var asked []string
	var mu sync.Mutex
	p := spyDefaults(&asked, &mu)
	ctx := context.Background()
	held := []string{"app.corp.internal", "printer.home.arpa", "nas.lan", "dc01.corp", "wiki.intranet"}
	for _, n := range held {
		a := p.Resolve(ctx, n)
		if want := n == "app.corp.internal" || n == "printer.home.arpa" || n == "nas.lan"; a.Live() != want {
			t.Errorf("Resolve(%s): %+v", n, a)
		}
		if _, err := p.Query(ctx, n, dns.TypeMX); !errors.Is(err, ErrHeld) {
			t.Errorf("Query(%s): %v", n, err)
		}
		if d := p.Lookup(ctx, n, LookupOptions{Types: []uint16{dns.TypeA, dns.TypeTXT}}); d.Answered() || len(d.Failures) != 2 {
			t.Errorf("Lookup(%s): %+v", n, d)
		}
	}
	if a := p.Resolve(ctx, "nas.lan"); a.Status != StatusOK || a.A[0] != "10.0.0.7" {
		t.Errorf("an answer of the system's resolver: %+v", a)
	}
	if len(asked) != 0 {
		t.Fatalf("sent to the default resolvers: %v", asked)
	}
	for _, n := range held {
		if !sys.has(n) {
			t.Errorf("the system's resolver was not asked for %s", n)
		}
	}
	// each name once, however many types and doors asked it
	want := "5 names (app.corp.internal, printer.home.arpa, nas.lan) are a single label or in a zone no public resolver can answer (a special-use name such as .test or .local, a top-level domain the root zone does not delegate such as .internal, .lan or .corp, or home.arpa): kept off the default public resolvers, which would only learn the names, and asked of the system's resolver instead: it answered 3; name your own resolvers with -resolvers to ask them instead"
	if n := p.HeldZoneNote(); n != want {
		t.Errorf("note %q", n)
	}
	if n := p.HeldNote(); n != "" {
		t.Errorf("a reverse note for forward names: %q", n)
	}
	if a := p.Resolve(ctx, "app.example.com"); a.Status == StatusReserved {
		t.Errorf("a delegated TLD: %+v", a)
	}
	if _, err := p.Query(ctx, "www.example.web", dns.TypeA); err != nil {
		t.Errorf("a delegated TLD the public suffix list lacks: %v", err)
	}
	seen := map[string]bool{} // an empty answer is asked again of a second resolver
	for _, n := range askedNames(&asked) {
		seen[n] = true
	}
	if len(seen) != 2 || !seen["app.example.com."] || !seen["www.example.web."] {
		t.Errorf("asked %v", asked)
	}
	if n := p.HeldZoneNote(); !strings.HasPrefix(n, "5 names") {
		t.Errorf("a name that was asked of the defaults was held: %q", n)
	}
}

func TestNamedResolversAreAskedForNamesInUndelegatedZones(t *testing.T) {
	sys := startSystem(t, map[string]string{"c.lan": "10.0.0.1"})
	var got []string
	var mu sync.Mutex
	named := New(Options{Resolvers: []string{"192.0.2.53:53"}, PerSecond: -1})
	named.Exchange = func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
		mu.Lock()
		got = append(got, strings.ToLower(m.Question[0].Name))
		mu.Unlock()
		r := new(dns.Msg)
		r.SetReply(m)
		return r, nil
	}
	ctx := context.Background()
	for _, n := range []string{"a.internal", "b.home.arpa", "c.lan", "d.corp"} {
		if named.Held(n) || named.Reserved(n) {
			t.Errorf("%s is held with -resolvers", n)
		}
		named.Resolve(ctx, n)
	}
	uniq := map[string]bool{} // an empty answer is asked again
	for _, g := range got {
		uniq[g] = true
	}
	if len(uniq) != 4 || named.HeldZoneNote() != "" || sys.count("A") != 0 {
		t.Errorf("asked %v, note %q, the system's resolver %d times", got, named.HeldZoneNote(), sys.count("A"))
	}
}

func TestHeldZoneNoteSaysOneName(t *testing.T) {
	startSystem(t, map[string]string{})
	var asked []string
	var mu sync.Mutex
	p := spyDefaults(&asked, &mu)
	p.Resolve(context.Background(), "x.internal")
	if n := p.HeldZoneNote(); !strings.HasPrefix(n, "1 name (x.internal) is a single label or in a zone") || !strings.Contains(n, "it answered 0;") {
		t.Errorf("note %q", n)
	}
}
