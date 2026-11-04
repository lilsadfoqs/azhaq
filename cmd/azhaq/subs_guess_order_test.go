package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// orderResolver answers the names it is given and logs each A question in
// the order it arrived.
func orderResolver(t *testing.T, exist ...string) (addr string, order func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	known := map[string]bool{}
	for _, n := range exist {
		known[dns.Fqdn(n)] = true
	}
	var mu sync.Mutex
	var log []string
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		if q.Qtype == dns.TypeA {
			mu.Lock()
			log = append(log, strings.TrimSuffix(strings.ToLower(q.Name), "."))
			mu.Unlock()
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if known[strings.ToLower(q.Name)] && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")})
		} else if !known[strings.ToLower(q.Name)] {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), log...)
	}
}

// A polite -live run looks up subdomain.center's guesses, and a name a
// source gives while they are being looked up is asked behind a few seconds
// of the rate of them, not behind every guess queued: with -dns-rate 10 at
// most 40 are in flight, where 128 were (and 300 guesses were all queued
// before the name came).
func TestSubsLiveNamedNamesWaitBehindFewGuesses(t *testing.T) {
	var guesses []string
	for i := 0; i < 300; i++ {
		guesses = append(guesses, fmt.Sprintf("g%03d.example.org", i))
	}
	named := []string{"n0.example.org", "n1.example.org", "n2.example.org"}
	resolver, order := orderResolver(t, named...)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "slow", Default: true, Names: named, Delay: 300 * time.Millisecond},
		subcol.TestSource{Name: "center", Default: true, Sampled: true, Padding: true, Names: guesses},
	)()
	t.Chdir(t.TempDir())
	_, rep, _ := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-dns-rate", "10", "-no-history", "-max-time", "8s", "-guess-samples", "1")
	at := map[string]int{}
	for i, n := range order() {
		if _, ok := at[n]; !ok {
			at[n] = i
		}
	}
	for _, n := range named {
		i, ok := at[n]
		if !ok {
			t.Fatalf("%s was not asked in 8 s (counts %v)", n, rep.Counts)
		}
		// Sent before the name came: about 10 a second for 0.3 s and the burst;
		// ahead of it in the pace: the window of 40. With 128 in flight it
		// is not asked in the 8 s.
		if i > 90 {
			t.Errorf("%s was the %dth question: it waited behind %d guesses, more than the window of 40 and the few sent before it came", n, i+1, i)
		}
	}
}

// A -live run says how many of the names only subdomain.center held it looked
// up and what came of them, and the numbers are the rows and the counts.
func TestSubsLiveSaysHowManyGuessesWereLookedUp(t *testing.T) {
	var guesses []string
	for i := 0; i < 60; i++ {
		guesses = append(guesses, fmt.Sprintf("g%02d.example.org", i))
	}
	real := []string{"g03.example.org", "g40.example.org", "g41.example.org", "n0.example.org"}
	resolver, order := orderResolver(t, real...)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"n0.example.org"}},
		subcol.TestSource{Name: "center", Default: true, Sampled: true, Padding: true, Names: guesses},
	)()
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-guess-samples", "1")
	if code != exitOK {
		t.Fatalf("exit %d, notes %v", code, rep.Notes)
	}
	resolved := 0
	for _, l := range lines(out) {
		if strings.Contains(l, `"source":"center"`) {
			resolved++
		}
	}
	want := fmt.Sprintf("the %d names only center held were looked up in DNS in", len(guesses))
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, want) || !strings.Contains(notes, fmt.Sprintf(": %d resolved, %d did not exist", resolved, rep.Counts["did not resolve"])) || resolved != 3 {
		t.Errorf("the note does not say %q with %d resolved and %d not existing (the rows and the counts):\n%s", want, resolved, rep.Counts["did not resolve"], notes)
	}
	var asked int
	for _, n := range order() {
		if strings.HasPrefix(n, "g") {
			asked++
		}
	}
	if asked != len(guesses) {
		t.Errorf("%d guesses reached the resolver, the note says %d were looked up", asked, len(guesses))
	}
}

// -live -guesses=false looks up the names the sources gave and leaves
// subdomain.center's guesses unlooked: none reaches the resolver, none is
// printed, the summary counts them held back, and the run is complete.
func TestSubsLiveWithoutGuessesLeavesThemUnlooked(t *testing.T) {
	var guesses []string
	for i := 0; i < 60; i++ {
		guesses = append(guesses, fmt.Sprintf("g%02d.example.org", i))
	}
	resolver, order := orderResolver(t, "g03.example.org", "n0.example.org")
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"n0.example.org", "dead.example.org"}},
		subcol.TestSource{Name: "center", Default: true, Sampled: true, Padding: true, Names: guesses},
	)()
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-guesses=false", "-resolvers", resolver, "-no-history")
	if code != exitOK || len(rep.Failed) != 0 {
		t.Fatalf("exit %d, failed %+v, notes %v", code, rep.Failed, rep.Notes)
	}
	if strings.Contains(out, "g03.example.org") || !strings.Contains(out, "n0.example.org") || rep.Results != 1 {
		t.Errorf("rows:\n%s", out)
	}
	if rep.Counts["guesses held back"] != len(guesses) || rep.Counts["not checked"] != 0 || rep.Counts["did not resolve"] != 1 {
		t.Errorf("counts %v: the 60 guesses are held back, and only dead.example.org did not resolve", rep.Counts)
	}
	for _, n := range order() {
		if strings.HasPrefix(n, "g") {
			t.Fatalf("a guess was looked up: %s", n)
		}
	}
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "60 names are held back") || strings.Contains(notes, "could not be checked") {
		t.Errorf("notes:\n%s", notes)
	}
}

// An explicit -guesses with -live is still refused: it asks to print names
// no lookup checked.
func TestSubsLiveRefusesAnExplicitGuesses(t *testing.T) {
	t.Chdir(t.TempDir())
	_, _, code := runContract(t, "subs", "-d", "example.org", "-live", "-guesses")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}
