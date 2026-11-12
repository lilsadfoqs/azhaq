package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/dnsr"
)

// latZone is a resolver with the round trip of a public one: an A record
// for the names it holds, a CNAME and no address for some, NXDOMAIN for
// the rest.
type latZone struct {
	a     map[string]string
	cname map[string]string
	lat   time.Duration
}

func (z *latZone) handle(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	time.Sleep(z.lat/2 + time.Duration(rand.Int63n(int64(z.lat))))
	m := new(dns.Msg)
	m.SetReply(r)
	if ip, ok := z.a[name]; ok {
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(name + ". 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
	} else if c, ok := z.cname[name]; ok {
		rr, _ := dns.NewRR(name + ". 60 IN CNAME " + c + ".")
		m.Answer = append(m.Answer, rr)
		m.Rcode = dns.RcodeNameError
	} else {
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func serveLat(t *testing.T, z *latZone, n int) (file string, addrs []string) {
	t.Helper()
	for i := 0; i < n; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no UDP: %v", err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(z.handle)}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
		addrs = append(addrs, pc.LocalAddr().String())
	}
	file = filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(file, []byte(strings.Join(addrs, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

// The time subs -live takes past its slowest source is what dnsx takes for
// the same names, not more: a live name's wildcard probe of its parent zone
// and a CNAME target's registration are each a round trip, and asked one
// name after another (the batch's names under 100 zones) they were seconds
// after the last answer. Names of a big program's shape: a quarter live,
// each under a zone of its own, some CNAMEs to other domains, the rest not
// there, and answers at a public resolver's 40 to 120 ms.
func TestSubsLiveTimeIsTheSlowestSourcePlusDnsx(t *testing.T) {
	t.Chdir(t.TempDir())
	z := &latZone{a: map[string]string{}, cname: map[string]string{}, lat: 80 * time.Millisecond}
	var real []string
	for i := 0; i < 400; i++ {
		n := fmt.Sprintf("h%d.example.org", i)
		switch {
		case i%4 == 0:
			n = fmt.Sprintf("h%d.z%d.example.org", i, i)
			z.a[n] = fmt.Sprintf("192.0.2.%d", i%250+1)
		case i%20 == 1:
			z.cname[n] = fmt.Sprintf("x%d.elsewhere.net", i)
		}
		real = append(real, n)
	}
	file, addrs := serveLat(t, z, 2)
	const slowest = 1500 * time.Millisecond
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "slow", Default: true, Names: real, Delay: slowest},
		subcol.TestSource{Name: "fast", Default: true, Names: real[:150]},
	)()
	t0 := time.Now()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", file, "-no-history")
	took := time.Since(t0)
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	if n := len(lines(out)); n != 120 {
		t.Errorf("%d names printed, want the 100 that resolve and the 20 dangling CNAMEs", n)
	}

	// dnsx on the same names: A, AAAA and CNAME for each, 100 at a time.
	pool := dnsr.New(dnsr.Options{Resolvers: addrs})
	t1 := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)
	for _, n := range real {
		wg.Add(1)
		sem <- struct{}{}
		go func(n string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
				_, _ = pool.Query(t.Context(), n, qt)
			}
		}(n)
	}
	wg.Wait()
	dnsx := time.Since(t1)
	// 1.5x: a shared test runner's noise stays under it, and the serial probes
	// this guards against took about 2.6x; the bench row holds the 1.05x bar.
	limit := (slowest+dnsx)*150/100 + 250*time.Millisecond
	if raceOn {
		limit += time.Second
	}
	t.Logf("subs -live %s; slowest source %s + dnsx %s; bound %s", took.Round(time.Millisecond), slowest, dnsx.Round(time.Millisecond), limit.Round(time.Millisecond))
	if took > limit {
		t.Errorf("subs -live took %s, the bar is its slowest source %s plus dnsx %s, 1.5x: %s", took, slowest, dnsx, limit)
	}
}
