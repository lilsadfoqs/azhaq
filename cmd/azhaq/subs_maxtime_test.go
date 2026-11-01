package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// slowResolver answers A for the names given after delay and NXDOMAIN for
// any other, and counts the queries.
func slowResolver(t *testing.T, delay time.Duration, names ...string) (addr string, asked *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	known := map[string]bool{}
	for _, n := range names {
		known[dns.Fqdn(n)] = true
	}
	asked = new(atomic.Int32)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		asked.Add(1)
		time.Sleep(delay)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case known[strings.ToLower(q.Name)] && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")})
		case !known[strings.ToLower(q.Name)]:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), asked
}

// -max-time bounds the whole subs run, the DNS checks of -live included: the
// sources answer at once and the resolver is slow, and the run stops at the
// bound with exit 4, naming the flag and the names it did not ask.
func TestSubsMaxTimeBoundsTheLiveDNSPhase(t *testing.T) {
	var names []string
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("n%02d.example.org", i))
	}
	resolver, asked := slowResolver(t, 100*time.Millisecond, names...)
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: names})()
	t.Chdir(t.TempDir())
	t0 := time.Now()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-dns-rate", "5", "-no-history", "-max-time", "3s")
	took := time.Since(t0)
	if took > 8*time.Second {
		t.Errorf("-max-time 3s: the run took %s (%d queries; 40 names at 5 a second take 8 s)", took, asked.Load())
	}
	if code != exitLimit || rep.Complete || !strings.Contains(rep.Stopped, "-max-time 3s") {
		t.Errorf("exit %d, stopped %q: a run cut by -max-time is a stop that names the flag", code, rep.Stopped)
	}
	left := rep.Counts["not asked"]
	if left == 0 || left+rep.Results != 40 {
		t.Errorf("counts %v, results %d: the names not asked and those printed are the 40 names", rep.Counts, rep.Results)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), fmt.Sprintf("%d names were not asked in DNS before the run stopped", left)) {
		t.Errorf("no note says what was left: %v", rep.Notes)
	}
}

// The same for subdomain.center's guesses, which are looked up as its rounds
// arrive: the bound ends them, the names whose lookup was cut are said to be
// cut by the run's stop and not by failing resolvers, and a live row is never
// marked unverified.
func TestSubsMaxTimeBoundsSampledGuessesToo(t *testing.T) {
	var names, guesses []string
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("n%02d.example.org", i))
	}
	for i := 0; i < 300; i++ {
		guesses = append(guesses, fmt.Sprintf("g%03d.example.org", i))
	}
	resolver, _ := slowResolver(t, 100*time.Millisecond, append(names, guesses[:5]...)...)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: names},
		subcol.TestSource{Name: "center", Default: true, Sampled: true, Padding: true, Names: guesses},
	)()
	t.Chdir(t.TempDir())
	t0 := time.Now()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-dns-rate", "5", "-no-history", "-max-time", "4s")
	if took := time.Since(t0); took > 8*time.Second {
		t.Errorf("-max-time 4s: the run took %s", took)
	}
	if code != exitLimit || !strings.Contains(rep.Stopped, "-max-time 4s") {
		t.Fatalf("exit %d, stopped %q", code, rep.Stopped)
	}
	notes := strings.Join(rep.Notes, "\n")
	if rep.Counts["not checked"] == 0 || !strings.Contains(notes, fmt.Sprintf("%d names could not be checked (the run stopped first)", rep.Counts["not checked"])) {
		t.Errorf("counts %v, notes %v: the cut guesses are not said to be cut by the stop", rep.Counts, rep.Notes)
	}
	if strings.Contains(out, `"unverified"`) || rep.Counts["unverified"] != 0 {
		t.Errorf("a row of -live is marked unverified:\n%s", out)
	}
	if got := rep.Results + rep.Counts["not checked"] + rep.Counts["not asked"] + rep.Counts["did not resolve"]; got != rep.Counts["from sources"] {
		t.Errorf("counts %v, results %d: the names do not add up (%d of %d)", rep.Counts, rep.Results, got, rep.Counts["from sources"])
	}
}

// -timeout and -max-time both bound a subs run: the shorter one applies and
// is the one named. Without -live the names the sources gave are kept and a
// source still asking is what was left.
func TestSubsMaxTimeEndsASlowSourceAsAStop(t *testing.T) {
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "fast", Default: true, Names: []string{"a.example.org", "b.example.org"}},
		subcol.TestSource{Name: "slow", Default: true, Names: []string{"c.example.org"}, Delay: 30 * time.Second},
	)()
	t.Chdir(t.TempDir())
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-max-time", "2s"}, "-max-time 2s"},
		{[]string{"-max-time", "2s", "-timeout", "30s"}, "-max-time 2s"},
		{[]string{"-max-time", "30s", "-timeout", "2s"}, "-timeout 2s"},
	} {
		t0 := time.Now()
		out, rep, code := runContract(t, append([]string{"subs", "-d", "example.org", "-no-history"}, c.args...)...)
		if took := time.Since(t0); took > 6*time.Second {
			t.Errorf("%v: the run took %s", c.args, took)
		}
		if code != exitLimit || !strings.Contains(rep.Stopped, c.want+" reached") || rep.Results != 2 {
			t.Errorf("%v: exit %d, stopped %q, %d results:\n%s", c.args, code, rep.Stopped, rep.Results, out)
		}
	}
}
