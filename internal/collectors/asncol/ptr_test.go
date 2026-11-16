package asncol

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/types"
)

func ptrPool(resolvers []string, asked *[]string, mu *sync.Mutex) *dnsr.Pool {
	p := dnsr.New(dnsr.Options{Resolvers: resolvers, PerSecond: -1, Timeout: time.Second})
	p.Exchange = func(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
		mu.Lock()
		*asked = append(*asked, strings.ToLower(m.Question[0].Name))
		mu.Unlock()
		r := new(dns.Msg)
		r.SetReply(m)
		r.Answer = append(r.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "host.example.org."})
		return r, nil
	}
	return p
}

func prefixSeeds(ips ...string) []types.Seed {
	var out []types.Seed
	for _, ip := range ips {
		out = append(out, types.Seed{Type: types.TypeIPAddress, Keys: map[string]string{"ip": ip, "from": FromPrefix}})
	}
	return out
}

var local = []string{"127.31.0.1", "10.1.2.3", "172.20.0.4", "192.168.7.8", "100.64.1.1", "169.254.3.3", "fd00::5", "fe80::7"}

// systemStub replaces the system's resolver with a DNS server on loopback
// that answers every PTR with sys.example.org. and counts the questions.
func systemStub(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		if q.Qtype == dns.TypePTR {
			n.Add(1)
			m.Answer = append(m.Answer, &dns.PTR{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "sys.example.org."})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	restore := egress.SetSystemResolver(&net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}})
	t.Cleanup(func() { restore(); _ = srv.Shutdown() })
	return &n
}

// Without -resolvers the pool is the default public one: the reverse names
// of loopback, private, shared and link-local addresses are asked of the
// system's resolver, not of it (a pool whose Exchange records what would go
// out sees none), and the pool counts them and what the system answered. A
// public address is asked of the pool.
func TestPTRAsksTheSystemNotTheDefaultResolversForLocalAddresses(t *testing.T) {
	sys := systemStub(t)
	var asked []string
	var mu sync.Mutex
	pool := ptrPool(nil, &asked, &mu)
	r := &PTR{Pool: pool}
	var names []string
	metas, err := r.RunBatch(context.Background(), prefixSeeds(append(append([]string{}, local...), "8.8.8.8")...), func(_ types.Seed, o types.Observation) error {
		names = append(names, string(o.Payload))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "8.8.8.8.in-addr.arpa." {
		t.Fatalf("asked %v, want only the public address's reverse name", asked)
	}
	if len(names) != len(local)+1 || len(metas) != len(local)+1 {
		t.Errorf("emitted %d, %d metas", len(names), len(metas))
	}
	if sys.Load() != int64(len(local)) {
		t.Errorf("the system's resolver was asked %d times, want %d", sys.Load(), len(local))
	}
	if n := pool.HeldNote(); !strings.HasPrefix(n, "8 reverse lookups") || !strings.Contains(n, "it answered 8;") {
		t.Errorf("note %q", n)
	}
}

// A resolver the user named is asked for every reverse name, as dnsx does.
func TestPTRAsksNamedResolversForLocalAddresses(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	pool := ptrPool([]string{"192.0.2.53:53"}, &asked, &mu)
	r := &PTR{Pool: pool}
	if _, err := r.RunBatch(context.Background(), prefixSeeds(local...), func(types.Seed, types.Observation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(asked) != len(local) || pool.HeldNote() != "" {
		t.Errorf("asked %d of %d, note %q", len(asked), len(local), pool.HeldNote())
	}
}
