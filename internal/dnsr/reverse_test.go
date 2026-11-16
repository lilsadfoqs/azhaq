package dnsr

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLocalReverse(t *testing.T) {
	for name, want := range map[string]bool{
		"1.0.0.127.in-addr.arpa.":  true,
		"5.1.168.192.in-addr.arpa": true,
		"9.0.0.10.in-addr.arpa":    true,
		"4.3.2.172.in-addr.arpa":   false, // 172.2.3.4 is public
		"1.1.16.172.in-addr.arpa":  true,  // 172.16.1.1
		"1.1.31.172.in-addr.arpa":  true,
		"1.1.32.172.in-addr.arpa":  false,
		"1.1.15.172.in-addr.arpa":  false,
		"9.0.64.100.in-addr.arpa":  true, // 100.64.0.9, RFC 6598
		"9.0.128.100.in-addr.arpa": false,
		"7.1.254.169.in-addr.arpa": true,
		"8.8.8.8.in-addr.arpa":     false,
		"10.in-addr.arpa":          true,
		"168.192.in-addr.arpa":     true,
		"16.172.in-addr.arpa":      true,
		"172.in-addr.arpa":         false,
		"in-addr.arpa":             false,
		"01.0.0.127.in-addr.arpa":  false, // not a canonical label
		"example.com":              false,
		"1.0.0.127.example.com":    false,
	} {
		if got := LocalReverse(name); got != want {
			t.Errorf("LocalReverse(%q) = %v, want %v", name, got, want)
		}
	}
	for addr, want := range map[string]bool{
		"::1": true, "fd00::7": true, "fc12::1": true, "fe80::1": true, "febf::1": true,
		"fec0::1": false, "2001:db8::1": false, "2606:4700::1111": false,
	} {
		rev, err := dns.ReverseAddr(addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := LocalReverse(rev); got != want {
			t.Errorf("LocalReverse(%s = %s) = %v, want %v", addr, rev, got, want)
		}
		if got := LocalAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("LocalAddr(%s) = %v, want %v", addr, got, want)
		}
	}
	for _, zone := range []string{"d.f.ip6.arpa", "0.8.e.f.ip6.arpa"} {
		if !LocalReverse(zone) { // fd00::/8, fe80::/12... of fe80::/10
			t.Errorf("LocalReverse(%q) = false", zone)
		}
	}
	if LocalReverse("0.0.0.0.ip6.arpa") || LocalReverse("ip6.arpa") {
		t.Error("a zone of public addresses is not local")
	}
}

// spyDefaults is a pool on the default resolvers whose network call is
// replaced: it records what would have been sent, and sends nothing.
func spyDefaults(asked *[]string, mu *sync.Mutex) *Pool {
	p := New(Options{PerSecond: -1, Timeout: time.Second})
	p.Exchange = func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
		mu.Lock()
		*asked = append(*asked, dns.TypeToString[m.Question[0].Qtype]+" "+strings.ToLower(m.Question[0].Name)+" @"+server)
		mu.Unlock()
		r := new(dns.Msg)
		r.SetReply(m)
		return r, nil
	}
	return p
}

// The default pool does not send the reverse name of a loopback, private,
// shared or link-local address, whatever the type asked: it asks the
// system's resolver for a PTR and counts the lookup and its answer, and
// sends no other type anywhere. A public address's reverse name goes out, and
// so does everything to a pool whose resolvers the user named.
func TestDefaultPoolAsksTheSystemForReverseNamesOfLocalAddresses(t *testing.T) {
	sys := startSystem(t, map[string]string{"10.0.0.2": "db.corp.", "fd12::5": "v6.corp."})
	var asked []string
	var mu sync.Mutex
	p := spyDefaults(&asked, &mu)
	ctx := context.Background()
	answered := 0
	for _, ip := range []string{"127.31.0.1", "10.0.0.2", "172.16.5.5", "192.168.1.1", "100.64.3.3", "169.254.9.9", "fd12::5", "fe80::9"} {
		rev, _ := dns.ReverseAddr(ip)
		m, err := p.Query(ctx, rev, dns.TypePTR)
		if err != nil {
			t.Errorf("%s: %v", ip, err)
			continue
		}
		if len(m.Answer) > 0 {
			answered++
			if ptr := m.Answer[0].(*dns.PTR).Ptr; ptr != map[string]string{"10.0.0.2": "db.corp.", "fd12::5": "v6.corp."}[ip] {
				t.Errorf("%s: %s", ip, ptr)
			}
		}
	}
	if answered != 2 {
		t.Errorf("%d answers, want the 2 the system's resolver has", answered)
	}
	if _, err := p.Query(ctx, "10.in-addr.arpa", dns.TypeSOA); !errors.Is(err, ErrHeld) {
		t.Errorf("a private reverse zone: %v", err)
	}
	if _, err := p.Query(ctx, "2.0.0.10.in-addr.arpa", dns.TypeTXT); !errors.Is(err, ErrHeld) {
		t.Errorf("another type: %v", err)
	}
	if len(asked) != 0 {
		t.Fatalf("sent to the default resolvers: %v", asked)
	}
	if sys.count("PTR") < 8 {
		t.Errorf("the system's resolver was asked %d times", sys.count("PTR"))
	}
	want := "8 reverse lookups (1.0.31.127.in-addr.arpa, 2.0.0.10.in-addr.arpa, 5.5.16.172.in-addr.arpa) of loopback, private or link-local addresses were kept off the default public resolvers, which are not given the addresses of a private network, and asked of the system's resolver instead: it answered 2; name your own resolvers with -resolvers to ask them instead"
	if n := p.HeldNote(); n != want {
		t.Errorf("note %q", n)
	}
	if _, err := p.Query(ctx, "8.8.8.8.in-addr.arpa", dns.TypePTR); err != nil || len(asked) != 1 {
		t.Errorf("a public address's reverse name: err %v, asked %v", err, asked)
	}
	var got []string
	var mu2 sync.Mutex
	named := New(Options{Resolvers: []string{"192.0.2.53:53"}, PerSecond: -1, Timeout: time.Second})
	named.Exchange = func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
		mu2.Lock()
		got = append(got, m.Question[0].Name)
		mu2.Unlock()
		r := new(dns.Msg)
		r.SetReply(m)
		return r, nil
	}
	before := sys.count("PTR")
	rev, _ := dns.ReverseAddr("127.0.0.1")
	if _, err := named.Query(ctx, rev, dns.TypePTR); err != nil || len(got) != 1 || named.HeldNote() != "" || named.Held(rev) || sys.count("PTR") != before {
		t.Errorf("named resolver: err %v, asked %v, note %q", err, got, named.HeldNote())
	}
}
