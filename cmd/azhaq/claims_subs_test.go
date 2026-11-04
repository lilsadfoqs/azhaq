package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// sourceProxy stands in for every third party a source asks: it is the run's
// -proxy, answers 502 and counts what reaches it. (The proxy of the
// environment is read once per process, so a test cannot rely on it.)
func sourceProxy(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Error(w, "caught", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

// ledgerClasses counts the lines of a ledger file by class.
func ledgerClasses(t *testing.T, path string) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind != ledger.KindSeal {
			out[e.Class]++
		}
		return nil
	}); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// Without -live no name is looked up: no query reaches a resolver, the ledger
// holds no DNS line, the names are printed as candidates, and the next: line
// that offers -live is a line, not a lookup.
func TestSubsWithoutLiveLooksNothingUp(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	resolver, asked := slowResolver(t, 0, "www.example.org")
	// An earlier run leaves www in the name history.
	restore := subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org"}},
		subcol.TestSource{Name: "history", Default: true},
	)
	if _, _, code := cli(t, "subs", "-d", "example.org", "-silent"); code != exitOK {
		t.Fatalf("first run: exit %d", code)
	}
	restore()
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"api.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Names: []string{"guess1.example.org", "guess2.example.org"}},
		subcol.TestSource{Name: "history", Default: true},
	)()
	atTerminal(t)
	stdout, stderr, code := cli(t, "subs", "-d", "example.org", "-resolvers", resolver, "-db", "w.db", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, r := range jsonRows(t, stdout) {
		if r["tier"] != "candidate" {
			t.Errorf("%v: tier %v, want candidate", r["host"], r["tier"])
		}
	}
	if got := hosts(t, stdout); len(got) != 4 {
		t.Errorf("printed %v: the name of the source, the history's and the two guesses are candidates", got)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times without -live", n)
	}
	rep := sumMap(t, stderr)
	if q := rep["dns_queries"]; q != nil && q != float64(0) {
		t.Errorf("summary dns_queries %v", q)
	}
	if got := ledgerClasses(t, "w.db.ledger.jsonl"); got[ledger.ClassDNS] != 0 {
		t.Errorf("the ledger holds DNS lines: %v", got)
	}
	_, text := runText(t, "subs", "-d", "example.org", "-resolvers", resolver)
	if next := nextLines(text); len(next) == 0 || !strings.Contains(next[0], "-live   (next pass, not run:") {
		t.Errorf("no next: line that offers -live:\n%s", text)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times by the time the next: line was printed", n)
	}
}

// With -db the queries (and the requests to sources) go in DB.ledger.jsonl;
// without it, in the file -ledger names; with neither, nowhere. A source's
// request is in the ledger and is not one of the summary's requests, which
// are the ones sent to targets.
func TestSubsLedgerGoesWhereTheFlagsSay(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	proxy, caught := sourceProxy(t)
	resolver := serveZone(t, fakeZone{a: map[string]string{"app.example.org": "192.0.2.1"}})
	words := wlist(t, "app", "nope")
	base := []string{"subs", "-d", "example.org", "-sources", "hackertarget", "-w", words, "-resolvers", resolver, "-no-history", "-source-timeout", "5s", "-proxy", proxy}

	_, errOut, _ := cli(t, append(base, "-db", "w.db", "-json")...)
	got := ledgerClasses(t, "w.db.ledger.jsonl")
	if got[ledger.ClassDNS] == 0 || got[ledger.ClassSource] == 0 {
		t.Errorf("-db: the ledger holds %v, want DNS queries and the source's request", got)
	}
	if caught.Load() == 0 {
		t.Errorf("the source's request never reached the stand-in: the ledger line proves nothing")
	}
	if rep := sumMap(t, errOut); rep["requests"] != float64(0) {
		t.Errorf("requests %v: a source is not a target", rep["requests"])
	}

	led := filepath.Join(dir, "named.jsonl")
	cli(t, append(base, "-ledger", led, "-json")...)
	if got := ledgerClasses(t, led); got[ledger.ClassDNS] == 0 || got[ledger.ClassSource] == 0 {
		t.Errorf("-ledger FILE: the file holds %v", got)
	}

	other := t.TempDir()
	t.Chdir(other)
	cli(t, append(base, "-json")...)
	left, _ := filepath.Glob(filepath.Join(other, "*"))
	if len(left) != 0 {
		t.Errorf("a run with neither -db nor -ledger wrote %v", left)
	}
}

// Every takeover candidate is in the summary with host, service, target,
// evidence and strength.
func TestSubsTakeoverCandidateIsInTheSummaryWithItsFields(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:      map[string]string{"www.example.org": "192.0.2.10"},
		cname:  map[string]string{"cdn.example.org": "gone.example.net", "shop.example.org": "azq-gone.azurewebsites.net"},
		nxGone: true,
	})
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "cdn.example.org", "shop.example.org"}})()
	_, errOut, code := cli(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	list, _ := sumMap(t, errOut)["takeover"].([]any)
	if len(list) != 2 {
		t.Fatalf("takeover %v", list)
	}
	for _, x := range list {
		row, _ := x.(map[string]any)
		for _, k := range []string{"host", "service", "target", "evidence", "strength"} {
			if s, _ := row[k].(string); s == "" {
				t.Errorf("takeover row %v lacks %s", row, k)
			}
		}
	}
}

// A name under two of the domains given is printed once and counted as listed
// under another domain, and the sum of the counts is the names printed.
func TestSubsAnotherDomainsNameIsCountedNotPrintedTwice(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true,
		Names: []string{"www.example.org", "www.dev.example.org", "api.dev.example.org"}})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-d", "dev.example.org", "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	seen := map[string]int{}
	for _, h := range hosts(t, out) {
		seen[h]++
	}
	for h, n := range seen {
		if n != 1 {
			t.Errorf("%s printed %d times", h, n)
		}
	}
	c := rep.Counts
	if c["listed under another domain"] == 0 {
		t.Fatalf("counts %v: a name under two domains is not counted", c)
	}
	if got := namesFromCounts(c); got != rep.Results || len(seen) != rep.Results {
		t.Errorf("the counts give %d names, %d were printed (%d rows): %v", got, rep.Results, len(seen), c)
	}
	if want := "− " + "1 listed under another domain"; !strings.Contains(strings.Join(rep.Notes, "\n"), want) && c["listed under another domain"] == 1 {
		t.Errorf("no count note says %q: %v", want, rep.Notes)
	}
}

// The sources block's names are what each source gave, before a filter or a
// DNS check: -m and -live leave them as they were.
func TestSubsSourceNamesAreCountedBeforeFilterAndDNS(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.10"}})
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "a", Default: true, Names: []string{"www.example.org", "api.example.org", "dev.example.org"}},
		subcol.TestSource{Name: "b", Default: true, Names: []string{"mail.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-m", "www.*", "-resolvers", resolvers, "-no-history")
	if code != exitOK || rep.Results != 1 {
		t.Fatalf("exit %d, %d results: %s", code, rep.Results, out)
	}
	if want := map[string]int{"a": 3, "b": 1}; !reflect.DeepEqual(rep.Sources.Names, want) {
		t.Errorf("names by source %v, want %v: one name is printed, and the others gave 4", rep.Sources.Names, want)
	}
}

// A source that needs a key and has none is not run and not asked: its status
// says so and the summary's counts leave it out. -ls marks it.
func TestSubsASourceWithoutItsKeyIsNotAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("CHAOS_API_KEY", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	proxy, catch := sourceProxy(t)
	_, rep, _ := runContract(t, "subs", "-d", "example.org", "-sources", "chaos", "-no-history", "-proxy", proxy, "-providers", filepath.Join(t.TempDir(), "none.yaml"))
	if rep.Counts["sources asked"] != 0 || rep.Counts["sources failed"] != 0 {
		t.Errorf("counts %v: a source with no key is not asked", rep.Counts)
	}
	if catch.Load() != 0 {
		t.Errorf("%d requests went out for a source with no key", catch.Load())
	}
}

// With -live the tiers: the DNS-confirmed rows are the ones resolved from the
// sources, the ones found by guessing and the CNAME targets; the raw
// candidates less what did not resolve are the ones resolved from the
// sources; and the tiers: note says what it counts, with -http not asked.
func TestSubsTiersNoteAndWhatTheConfirmedTierHolds(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"www.example.org": "192.0.2.10", "edge.example.org": "192.0.2.11", "app.example.org": "192.0.2.12"},
		cname: map[string]string{"cdn.example.org": "edge.example.org"},
	})
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "cdn.example.org", "stale.example.org"}})()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-w", wlist(t, "app", "nope"), "-resolvers", resolvers, "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	c := rep.Counts
	if c["found by guessing"] != 1 || c["found as CNAME targets"] != 1 || c["did not resolve"] != 2 {
		t.Fatalf("counts %v: want app found by guessing, edge a CNAME target, stale and nope not resolving", c)
	}
	if c["DNS-confirmed"] != c["resolved from sources"]+c["found by guessing"]+c["found as CNAME targets"] || c["DNS-confirmed"] != rep.Results {
		t.Errorf("DNS-confirmed %d is not resolved from sources %d + guessing %d + CNAME targets %d (printed %d)", c["DNS-confirmed"], c["resolved from sources"], c["found by guessing"], c["found as CNAME targets"], rep.Results)
	}
	// stale did not resolve; nope was a guess: it is in did not resolve and not in raw.
	if c["raw candidates"]-(c["did not resolve"]-1) != c["resolved from sources"] {
		t.Errorf("raw candidates %d less the source names that did not resolve is not resolved from sources %d: %v", c["raw candidates"], c["resolved from sources"], c)
	}
	var tiers string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "tiers: ") {
			tiers = n
		}
	}
	want := "tiers: 3 raw candidates (what the sources gave; a row's sources say who); 4 DNS-confirmed (resolved); HTTP-confirmed not asked (-http): a candidate is never counted as confirmed"
	if tiers != want {
		t.Errorf("tiers note %q, want %q", tiers, want)
	}
	// Without -live the note says DNS was not asked, and that HTTP was not.
	_, rep, _ = runContract(t, "subs", "-d", "example.org", "-no-history")
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "tiers: ") && !strings.Contains(n, "DNS-confirmed not asked (-live); HTTP-confirmed not asked (-http)") {
			t.Errorf("tiers note %q", n)
		}
	}
}

// -guesses=false holds back only what no source asserted: a name the name
// history holds, though a guessing source gave it too, is printed.
func TestSubsGuessesFalseKeepsANameTheHistoryHolds(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"old.example.org"}},
		subcol.TestSource{Name: "history", Default: true},
	)
	if _, _, code := runContract(t, "subs", "-d", "example.org"); code != exitOK {
		t.Fatalf("first run: exit %d", code)
	}
	restore()
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Names: []string{"old.example.org", "junk.example.org"}},
		subcol.TestSource{Name: "history", Default: true},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-guesses=false")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	if got := hosts(t, out); !reflect.DeepEqual(got, []string{"old.example.org"}) || rep.Counts["guesses held back"] != 1 {
		t.Errorf("printed %v, counts %v: the history's name is not a guess, junk is", got, rep.Counts)
	}
}

// For more than three domains one note counts what the name history gave and
// took; for fewer each domain has its own. -no-history says nothing of it and
// writes nothing; a file that cannot be written is a note.
func TestSubsNameHistoryNotes(t *testing.T) {
	t.Chdir(t.TempDir())
	names := []string{"www.one.org", "www.two.org", "www.three.org", "www.four.org"}
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: names}, subcol.TestSource{Name: "history", Default: true})()
	count := func(rep report, prefix string) (n int) {
		for _, note := range rep.Notes {
			if strings.HasPrefix(note, prefix) {
				n++
			}
		}
		return n
	}
	for _, tc := range []struct {
		domains          []string
		perDomain, joint int
	}{{[]string{"one.org", "two.org", "three.org"}, 3, 0}, {[]string{"one.org", "two.org", "three.org", "four.org"}, 0, 1}} {
		var args []string
		for _, d := range tc.domains {
			args = append(args, "-d", d)
		}
		_, rep, _ := runContract(t, append([]string{"subs"}, args...)...)
		if got := count(rep, "name history /"); got != tc.perDomain {
			t.Errorf("%d domains: %d notes of a file, want %d: %q", len(tc.domains), got, tc.perDomain, rep.Notes)
		}
		if got := count(rep, "name history ("); got != tc.joint {
			t.Errorf("%d domains: %d notes that count them all, want %d: %q", len(tc.domains), got, tc.joint, rep.Notes)
		}
	}
	dir, _ := dataDirs.Load(t.Name())
	_, rep, _ := runContract(t, "subs", "-d", "one.org", "-no-history")
	if got := count(rep, "name history"); got != 0 {
		t.Errorf("-no-history: %q", rep.Notes)
	}
	before, _ := os.ReadFile(filepath.Join(dir.(string), "names", "one.org.json"))
	cli(t, "subs", "-d", "one.org", "-no-history", "-json")
	if after, _ := os.ReadFile(filepath.Join(dir.(string), "names", "one.org.json")); string(before) != string(after) {
		t.Errorf("-no-history changed the file:\n%s\n%s", before, after)
	}
	// A file that cannot be written: the directory is a regular file.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "names"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZHAQ_DATA_DIR", bad)
	_, errOut, code := cli(t, "subs", "-d", "one.org", "-json")
	if rep := sumMap(t, errOut); code != exitOK || !strings.Contains(strings.Join(strs(rep["notes"]), "\n"), "name history not saved: ") {
		t.Errorf("exit %d, notes %v", code, rep["notes"])
	}
}

// A -live run the time limit stopped, with no -db: there is nothing to
// resume, and the note says to run again with -db FILE or without -live.
func TestSubsStoppedLiveWithoutDBSaysThereIsNothingToResume(t *testing.T) {
	defer subcol.UseTestSources(subcol.TestSource{Name: "history", Default: true})()
	t.Chdir(t.TempDir())
	dir, _ := dataDirs.LoadOrStore(t.Name(), t.TempDir())
	hist := `{"api.example.org": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}`
	for i := 0; i < 120; i++ {
		hist += fmt.Sprintf(`, "h%d.example.org": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}`, i)
	}
	if err := os.MkdirAll(filepath.Join(dir.(string), "names"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.(string), "names", "example.org.json"), []byte(hist+"}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", nxResolver(t), "-dns-rate", "20", "-max-time", "3s")
	notes := strings.Join(rep.Notes, "\n")
	if code != exitLimit || rep.Counts["not checked"] == 0 {
		t.Fatalf("exit %d, counts %v", code, rep.Counts)
	}
	if !strings.Contains(notes, fmt.Sprintf("%d names could not be checked (", rep.Counts["not checked"])) ||
		!strings.Contains(notes, "this run kept no database: run again with -db FILE to keep them for azhaq resume, or without -live to list them unverified") ||
		strings.Contains(notes, "azhaq resume -db") {
		t.Errorf("notes %s", notes)
	}
}

// A zone is probed for a wildcard only when a guess in it resolves, and then
// once, with one query when the probe is answered NXDOMAIN: 40 guesses that
// do not exist cost 40 queries, and one that resolves, 41.
func TestSubsLiveProbesAZoneForAWildcardOnlyWhenAGuessResolves(t *testing.T) {
	for _, resolving := range []int{0, 1} {
		t.Chdir(t.TempDir())
		var guesses []string
		a := map[string]string{}
		for i := 0; i < 40; i++ {
			n := fmt.Sprintf("g%d.example.org", i)
			guesses = append(guesses, n)
			if i < resolving {
				a[n] = "198.51.100.1"
			}
		}
		z := &countingZone{a: a, byType: map[string]int{}, byName: map[string]int{}}
		resolvers := serveCounting(t, z, 1)
		restore := subcol.UseTestSources(subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Names: guesses})
		_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history")
		restore()
		if code != exitOK || rep.Results != resolving {
			t.Fatalf("exit %d, %d results", code, rep.Results)
		}
		if got, want := int(z.total.Load()), 40+resolving; got != want {
			t.Errorf("%d resolving: %d queries, want %d (one for each guess, and one probe when a guess resolves)", resolving, got, want)
		}
		z.mu.Lock()
		if z.byType["A"] != 40+resolving {
			t.Errorf("queries by type %v: a guess costs an A", z.byType)
		}
		for n, k := range z.byName {
			if strings.HasPrefix(n, "g") && len(n) < 12 && k != 1 {
				t.Errorf("%s was asked %d times", n, k)
			}
		}
		z.mu.Unlock()
	}
}

// With -live the names are looked up at -dns-rate: the queries a resolver
// gets in any second are no more than the rate and its burst, and the run
// takes what the rate says.
func TestSubsLiveLooksUpAtTheDnsRate(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var at []time.Time
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	var names []string
	for i := 0; i < 40; i++ {
		names = append(names, fmt.Sprintf("n%d.example.org", i))
	}
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: names})()
	const rate, burst = 20, 4 // a fifth of the rate
	t0 := time.Now()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", pc.LocalAddr().String(), "-dns-rate", fmt.Sprint(rate), "-no-history")
	took := time.Since(t0)
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(at) < 40 {
		t.Fatalf("%d queries for 40 names", len(at))
	}
	for i := range at {
		in := 0
		for _, x := range at[i:] {
			if x.Sub(at[i]) < time.Second {
				in++
			}
		}
		if in > rate+burst+5 {
			t.Fatalf("%d queries in the second after query %d, the rate is %d", in, i, rate)
		}
	}
	if min := time.Duration(float64(len(at)-burst-1) / rate * float64(time.Second)); took < min*9/10 {
		t.Errorf("%d queries took %s, the rate says at least %s", len(at), took, min)
	}
}

// With -live a stored name counts only if it resolves now and not to a
// wildcard; a name that did not is not printed, and counted as not resolving.
func TestSubsLiveAStoredNameThatOnlyAWildcardAnswersIsNotKept(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		ip := "192.0.2.99" // the wildcard
		if strings.ToLower(q.Name) == "www.example.org." {
			ip = "192.0.2.10"
		}
		if q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	dir, _ := dataDirs.LoadOrStore(t.Name(), t.TempDir())
	if err := os.MkdirAll(filepath.Join(dir.(string), "names"), 0o755); err != nil {
		t.Fatal(err)
	}
	stored := `{"old.example.org": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}, "www.example.org": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}}`
	if err := os.WriteFile(filepath.Join(dir.(string), "names", "example.org.json"), []byte(stored), 0o644); err != nil {
		t.Fatal(err)
	}
	defer subcol.UseTestSources(subcol.TestSource{Name: "history", Default: true})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", pc.LocalAddr().String())
	if got := hosts(t, out); code != exitOK || !reflect.DeepEqual(got, []string{"www.example.org"}) {
		t.Errorf("exit %d, printed %v: old resolves only to the wildcard", code, got)
	}
	if rep.Counts["did not resolve"] != 1 {
		t.Errorf("counts %v", rep.Counts)
	}
}

// What the history keeps is what a source gave or DNS confirmed from one:
// not a name that only -w guessed and not a CNAME target.
func TestSubsHistoryKeepsNoGuessedAndNoCNAMETargetName(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"www.example.org": "192.0.2.10", "edge.example.org": "192.0.2.11", "app.example.org": "192.0.2.12"},
		cname: map[string]string{"cdn.example.org": "edge.example.org"},
	})
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "cdn.example.org"}}, subcol.TestSource{Name: "history", Default: true})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-w", wlist(t, "app"), "-resolvers", resolvers)
	if want := []string{"app.example.org", "cdn.example.org", "edge.example.org", "www.example.org"}; code != exitOK || !reflect.DeepEqual(hosts(t, out), want) {
		t.Fatalf("exit %d, printed %v %+v", code, hosts(t, out), rep.Counts)
	}
	dir, _ := dataDirs.Load(t.Name())
	raw, err := os.ReadFile(filepath.Join(dir.(string), "names", "example.org.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	var got []string
	for n := range stored {
		got = append(got, n)
	}
	sort.Strings(got)
	if want := []string{"cdn.example.org", "www.example.org"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the history holds %v, want %v: not app (guessed) and not edge (a CNAME target)", got, want)
	}
}

// -extra-wait 0 waits for the sources outside subfinder's set as long as
// -source-timeout: a slow one's names are kept.
func TestSubsExtraWaitZeroWaitsForTheSlowSource(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "core", Default: true, Names: []string{"www.example.org"}},
		subcol.TestSource{Name: "slowextra", Default: true, Extra: true, Names: []string{"late.example.org"}, Delay: 1500 * time.Millisecond},
	)()
	t0 := time.Now()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-extra-wait", "0", "-no-history")
	if got := hosts(t, out); code != exitOK || !reflect.DeepEqual(got, []string{"late.example.org", "www.example.org"}) || time.Since(t0) < 1400*time.Millisecond {
		t.Errorf("exit %d, printed %v after %s, counts %v", code, got, time.Since(t0), rep.Counts)
	}
	// The default, 5 s, cuts a source that takes longer; 0 does not.
	_, rep, _ = runContract(t, "subs", "-d", "example.org", "-extra-wait", "300ms", "-no-history")
	if rep.Counts["sources failed"] != 1 {
		t.Errorf("-extra-wait 300ms did not cut the 1.5 s source: %v", rep.Counts)
	}
}

// The wider pass is offered only to a run that looked nothing up and guessed
// nothing: with -permute the first next: line is not it.
func TestSubsNoLivePassIsOfferedToARunThatGuesses(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.10"}})
	subsSources(t, "api.example.org", "www.example.org")
	atTerminal(t)
	_, errOut := runText(t, "subs", "-d", "example.org", "-no-history", "-permute", "-resolvers", resolvers)
	for _, n := range nextLines(errOut) {
		if strings.Contains(n, "next pass, not run") {
			t.Errorf("a run that guessed is offered the wider pass: %q", n)
		}
	}
	_, errOut = runText(t, "subs", "-d", "example.org", "-no-history", "-w", wlist(t, "www"), "-resolvers", resolvers)
	for _, n := range nextLines(errOut) {
		if strings.Contains(n, "next pass, not run") {
			t.Errorf("a run with -w is offered the wider pass: %q", n)
		}
	}
}

// With -live the names of the DNS-confirmed tier that the pool does not hold
// (guesses DNS confirmed, CNAME targets) are counted apart from it: the pool's
// names and the others add up to the names printed.
func TestSubsLiveCoverageAddsUpToTheNamesPrinted(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"www.example.org": "192.0.2.10", "api.example.org": "192.0.2.13", "edge.example.org": "192.0.2.11", "app.example.org": "192.0.2.12"},
		cname: map[string]string{"cdn.example.org": "edge.example.org"},
	})
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "a", Default: true, Names: []string{"www.example.org", "cdn.example.org", "api.example.org"}},
		subcol.TestSource{Name: "b", Default: true, Names: []string{"www.example.org", "stale.example.org"}},
	)()
	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-w", wlist(t, "app"), "-resolvers", resolvers, "-no-history")
	if code != exitOK || rep.Results != 5 {
		t.Fatalf("exit %d, %d results %v", code, rep.Results, rep.Counts)
	}
	var raw, dns string
	for _, n := range rep.Notes {
		switch {
		case strings.HasPrefix(n, "coverage (raw candidates): "):
			raw = n
		case strings.HasPrefix(n, "coverage (DNS-confirmed): "):
			dns = n
		}
	}
	if raw == "" || dns == "" {
		t.Fatalf("a note for each tier: %q", rep.Notes)
	}
	if !strings.Contains(raw, "what the independent sources know, not every name that exists") || strings.Contains(raw, "%") || strings.Contains(dns, "%") {
		t.Errorf("raw coverage note %q", raw)
	}
	// the pool holds www, cdn and api (3 live); app and edge came from elsewhere
	if !strings.Contains(dns, "this run has 3 of them") || !strings.Contains(dns, "the other 2 of the 5 names in this tier came from the name history, from guesses checked in DNS or as CNAME targets") {
		t.Errorf("DNS-confirmed coverage note %q", dns)
	}
}

// Names every resolver failed on by timing out are left out as no answer, not
// counted as not resolving, the note names the resolver and says it timed out,
// and the run ends with exit 3.
func TestSubsLiveNamesTheResolversThatTimedOut(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 10 s: a name is asked three times at 3 s")
	}
	t.Chdir(t.TempDir())
	resolver, _ := silentResolver(t)
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"a.example.org", "b.example.org"}})()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history")
	if code != exitPartial || out != "" || rep.Counts["no answer"] != 2 || rep.Counts["did not resolve"] != 0 {
		t.Fatalf("exit %d, printed %q, counts %v", code, out, rep.Counts)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "no answer from "+resolver+" for 2 names (timed out)") {
		t.Errorf("notes %q", rep.Notes)
	}
}

// dns asks resolvers, not sources: its summary has no sources block.
func TestDNSSummaryHasNoSourcesBlock(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	_, errOut, code := cli(t, "dns", "-d", "www.lab.zz", "-r", lab.addr, "-json")
	rep := sumMap(t, errOut)
	if _, has := rep["sources"]; has || code != exitOK {
		t.Errorf("exit %d, summary %v", code, rep)
	}
	if _, has := rep["counts"].(map[string]any)["sources asked"]; has {
		t.Errorf("counts %v", rep["counts"])
	}
}
