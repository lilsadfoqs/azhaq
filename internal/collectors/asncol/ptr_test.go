package asncol

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
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

var local = []string{"127.31.0.1", "10.1.2.3", "172.20.0.4", "192.168.7.8", "100.64.1.1", "169.254.3.3", "::1", "fd00::5", "fe80::7"}

// Without -resolvers the pool is the default public one: the reverse names
// of loopback, private, shared and link-local addresses are not asked of it
// (a pool whose Exchange records what would go out sees none), and the pool
// counts them. A public address is asked.
func TestPTRDoesNotAskTheDefaultResolversForLocalAddresses(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	pool := ptrPool(nil, &asked, &mu)
	r := &PTR{Pool: pool}
	var emitted int
	metas, err := r.RunBatch(context.Background(), prefixSeeds(append(append([]string{}, local...), "8.8.8.8")...), func(types.Seed, types.Observation) error { emitted++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "8.8.8.8.in-addr.arpa." {
		t.Fatalf("asked %v, want only the public address's reverse name", asked)
	}
	if emitted != 1 || len(metas) != len(local)+1 {
		t.Errorf("emitted %d, %d metas", emitted, len(metas))
	}
	if n := pool.HeldNote(); !strings.Contains(n, "not asked: 9 reverse lookups") {
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
