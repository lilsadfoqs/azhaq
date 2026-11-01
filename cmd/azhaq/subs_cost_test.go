package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// countingZone is a resolver that counts what it is asked, by type, and
// answers NXDOMAIN for every name outside its A records.
type countingZone struct {
	a        map[string]string
	mu       sync.Mutex
	byType   map[string]int
	byName   map[string]int
	total    atomic.Int32
	perQuery time.Duration
	// nodata names answer NOERROR with no records, as an empty non-terminal does.
	nodata map[string]bool
	// slow, if set, is the extra time a name's answer takes.
	slow func(name string) time.Duration
}

func (z *countingZone) handle(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	z.mu.Lock()
	z.byType[dns.TypeToString[q.Qtype]]++
	z.byName[name]++
	z.mu.Unlock()
	z.total.Add(1)
	time.Sleep(z.perQuery)
	if z.slow != nil {
		time.Sleep(z.slow(name))
	}
	m := new(dns.Msg)
	m.SetReply(r)
	ip, ok := z.a[name]
	switch {
	case z.nodata[name]:
	case !ok:
		m.Rcode = dns.RcodeNameError
	case q.Qtype == dns.TypeA:
		rr, _ := dns.NewRR(name + ". 60 IN A " + ip)
		m.Answer = append(m.Answer, rr)
	}
	_ = w.WriteMsg(m)
}

// serveCounting starts z on 127.0.0.1 and returns a -resolvers file with
// n copies of it: the pool then has a second resolver to confirm with.
func serveCounting(t *testing.T, z *countingZone, n int) string {
	t.Helper()
	var lines []string
	for i := 0; i < n; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no UDP: %v", err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(z.handle)}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
		lines = append(lines, pc.LocalAddr().String())
	}
	path := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// vulnwebShaped is a zone like vulnweb.com's passive result: real names from
// the sources, 8 of them resolving, and guesses over many parent zones, 4
// of them resolving.
func vulnwebShaped() (real, guesses []string, a map[string]string) {
	a = map[string]string{}
	for i := 0; i < 100; i++ {
		n := fmt.Sprintf("host%d.example.org", i)
		real = append(real, n)
		if i < 8 {
			a[n] = fmt.Sprintf("192.0.2.%d", i+1)
		}
	}
	for i := 0; i < 500; i++ {
		// a mix of one-label and deeper names, as the guesses are
		var n string
		switch i % 4 {
		case 0:
			n = fmt.Sprintf("g%d.example.org", i)
		case 1:
			n = fmt.Sprintf("g%d.com.example.org", i)
		default:
			n = fmt.Sprintf("g%d.p%d.example.org", i, i%97)
		}
		guesses = append(guesses, n)
		if i%125 == 3 {
			a[n] = fmt.Sprintf("198.51.100.%d", i%125+i/125+1)
		}
	}
	return
}

// costOf runs the vulnweb-shaped list against a counting resolver and
// returns the queries each kind of name cost.
func costOf(t *testing.T, z *countingZone, extra ...string) (perReal, perGuess float64, total int, took time.Duration, rows int) {
	t.Helper()
	t.Chdir(t.TempDir())
	real, guesses, a := vulnwebShaped()
	for n, v := range a {
		z.a[n] = v
	}
	z.byType, z.byName = map[string]int{}, map[string]int{}
	resolvers := serveCounting(t, z, 2)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: real},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Names: guesses},
	)()
	args := append([]string{"subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history"}, extra...)
	t0 := time.Now()
	out, rep, code := runContract(t, args...)
	took = time.Since(t0)
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	var rq, gq int
	for n, k := range z.byName {
		switch {
		case strings.HasPrefix(n, "host"):
			rq += k
		case strings.HasPrefix(n, "g"):
			gq += k
		}
	}
	return float64(rq) / float64(len(real)), float64(gq) / float64(len(guesses)), int(z.total.Load()), took, len(lines(out))
}

func TestSubsLiveQueryBreakdown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		perGuess float64
		z        func() *countingZone
	}{
		{"names that do not exist", 1.0, func() *countingZone { return &countingZone{} }},
		{"guesses under empty non-terminals (NODATA)", 2.0, func() *countingZone {
			_, guesses, _ := vulnwebShaped()
			nd := map[string]bool{}
			for _, g := range guesses {
				nd[g] = true
			}
			return &countingZone{nodata: nd}
		}},
		{"a third of the answers late", 1.05, func() *countingZone {
			return &countingZone{slow: func(n string) time.Duration {
				if len(n)%3 == 0 {
					return 400 * time.Millisecond
				}
				return 0
			}}
		}},
	} {
		z := tc.z()
		z.a = map[string]string{}
		if z.nodata == nil {
			z.nodata = map[string]bool{}
		}
		z.perQuery = time.Millisecond
		perReal, perGuess, total, took, rows := costOf(t, z, "-dns-rate", "1000")
		t.Logf("%s: %d queries in %s, %d printed; per real name %.2f, per guess %.2f; by type %v", tc.name, total, took.Round(time.Millisecond), rows, perReal, perGuess, z.byType)
		if perGuess > tc.perGuess {
			t.Errorf("%s: a guess cost %.2f queries, want at most %.2f", tc.name, perGuess, tc.perGuess)
		}
	}
}

// vulnweb's shape: about 100 names from the sources, and subdomain.center
// answering a new sample of 500 guesses over many parent zones on each call,
// 3 of each sample resolving. Every guess is looked up once, one query each
// at 2 resolvers that confirm nothing for a guess, every resolving guess is
// printed, and the run takes no longer than dnsx would for the same names
// at the same rate (names / rate).
func TestSubsLiveChecksEveryGuessAtDnsxCost(t *testing.T) {
	for _, resolvers := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d resolvers", resolvers), func(t *testing.T) { checksEveryGuess(t, resolvers) })
	}
}

func checksEveryGuess(t *testing.T, nResolvers int) {
	t.Chdir(t.TempDir())
	real, _, a := vulnwebShaped()
	const samples, per = 6, 500
	var rounds [][]string
	var guesses, live []string
	for r := 0; r < samples; r++ {
		var round []string
		for i := 0; i < per; i++ {
			var n string
			switch i % 4 {
			case 0:
				n = fmt.Sprintf("g%d-%d.example.org", r, i)
			case 1:
				n = fmt.Sprintf("g%d-%d.com.example.org", r, i)
			default:
				n = fmt.Sprintf("g%d-%d.p%d.example.org", r, i, i%97)
			}
			round = append(round, n)
			if i%167 == 5 { // 3 a sample
				a[n] = fmt.Sprintf("198.51.100.%d", len(live)+1)
				live = append(live, n)
			}
		}
		rounds = append(rounds, round)
		guesses = append(guesses, round...)
	}
	z := &countingZone{a: a, byType: map[string]int{}, byName: map[string]int{}, perQuery: time.Millisecond}
	resolvers := serveCounting(t, z, nResolvers)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: real},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Rounds: rounds},
	)()
	const rate = 1000
	t0 := time.Now()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-dns-rate", fmt.Sprint(rate), "-no-history")
	took := time.Since(t0)
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	z.mu.Lock()
	guessQ := 0
	for n, k := range z.byName {
		if strings.HasPrefix(n, "g") {
			if k != 1 {
				t.Errorf("%s was asked %d times", n, k)
			}
			guessQ += k
		}
	}
	z.mu.Unlock()
	if guessQ != len(guesses) {
		t.Errorf("%d queries for %d guesses", guessQ, len(guesses))
	}
	printed := map[string]bool{}
	for _, r := range jsonRows(t, out) {
		printed[r["host"].(string)] = true
	}
	for _, n := range live {
		if !printed[n] {
			t.Errorf("the resolving guess %s was not found", n)
		}
	}
	names := len(real) + len(guesses)
	dnsx := time.Duration(float64(names) / rate * float64(time.Second))
	t.Logf("%d names, %d queries (%.2f a name), %d printed in %s; dnsx at the same rate: %s", names, z.total.Load(), float64(z.total.Load())/float64(names), len(printed), took.Round(time.Millisecond), dnsx)
	// The queries say what the time is without a clock's noise (a busy
	// runner under -race missed a wall-clock bound): at the paced rate the
	// time is queries / rate / resolvers, so 1.05 a name is dnsx's time.
	if q := int(z.total.Load()); q > names*105/100 {
		t.Errorf("%d queries for %d names, more than 1.05 a name", q, names)
	}
}

// -guess-samples N takes up to N samples, and the note says what was left
// untaken and names the flag; a negative N is a usage error.
func TestSubsGuessSamplesFlag(t *testing.T) {
	t.Chdir(t.TempDir())
	real, _, a := vulnwebShaped()
	var rounds [][]string
	live := map[string]bool{}
	for r := 0; r < 4; r++ {
		var round []string
		for i := 0; i < 100; i++ {
			n := fmt.Sprintf("g%d-%d.p%d.example.org", r, i, i%17)
			round = append(round, n)
			if i == 7 {
				a[n] = "198.51.100.7"
				live[n] = true
			}
		}
		rounds = append(rounds, round)
	}
	z := &countingZone{a: a, byType: map[string]int{}, byName: map[string]int{}}
	resolvers := serveCounting(t, z, 1)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: real},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Rounds: rounds},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history", "-guess-samples", "2")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	got := 0
	for _, r := range jsonRows(t, out) {
		if live[r["host"].(string)] {
			got++
		}
	}
	if got != 2 {
		t.Errorf("%d resolving guesses of 2 samples found", got)
	}
	var said bool
	for _, n := range rep.Notes {
		said = said || strings.Contains(n, "was asked for 2 samples of its guesses") && strings.Contains(n, "the most samples were taken") && strings.Contains(n, "-guess-samples N")
	}
	if !said {
		t.Errorf("notes %q", rep.Notes)
	}
	if _, _, code := runContract(t, "subs", "-d", "example.org", "-guess-samples", "-1"); code != exitUsage {
		t.Errorf("-guess-samples -1: exit %d, want %d", code, exitUsage)
	}
}

// Resolvers that take a second or more to answer (a slow zone) are asked
// once per name under a pace, and answers up to 3 s are waited for, as dnsx
// waits: an attempt hedged beside every slow answer spent two or three
// slots of the rate on it, and a name that took 2.5 s failed at the 2 s
// timeout.
func TestSubsLiveSlowAnswersCostOneQueryAName(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 27 s")
	}
	for _, lat := range []time.Duration{1200 * time.Millisecond, 2500 * time.Millisecond} {
		z := &countingZone{a: map[string]string{}, byType: map[string]int{}, byName: map[string]int{}, nodata: map[string]bool{}, perQuery: lat}
		perReal, perGuess, total, took, rows := costOf(t, z, "-dns-rate", "100")
		t.Logf("answers in %s: %d queries in %s, %d printed; per real name %.2f, per guess %.2f", lat, total, took.Round(100*time.Millisecond), rows, perReal, perGuess)
		if perGuess > 1.0 || perReal > 2.0 || rows != 12 {
			t.Errorf("answers in %s: %.2f queries a guess, %.2f a real name, %d printed (want 1.0, 2.0, 12)", lat, perGuess, perReal, rows)
		}
	}
}
