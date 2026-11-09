package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/store"
)

// The guesses of subdomain.center are looked up by default with -live: the
// ones that resolve are printed, the ones that do not are counted in did not
// resolve, and an explicit -guesses is a usage error beside -live.
func TestSubsLiveGuessesThatResolveArePrintedAndTheRestAreCounted(t *testing.T) {
	var guesses []string
	for i := 0; i < 60; i++ {
		guesses = append(guesses, fmt.Sprintf("g%02d.example.org", i))
	}
	resolver, order := orderResolver(t, "g03.example.org", "g40.example.org", "g41.example.org", "n0.example.org")
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"n0.example.org"}},
		subcol.TestSource{Name: "center", Default: true, Sampled: true, Padding: true, Names: guesses},
	)()
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-guess-samples", "1")
	if code != exitOK {
		t.Fatalf("exit %d, notes %v", code, rep.Notes)
	}
	got := map[string]bool{}
	for _, h := range hosts(t, out) {
		got[h] = true
	}
	for _, want := range []string{"g03.example.org", "g40.example.org", "g41.example.org", "n0.example.org"} {
		if !got[want] {
			t.Errorf("%s resolves and was not printed: %v", want, got)
		}
	}
	if len(got) != 4 || rep.Counts["did not resolve"] != 57 {
		t.Errorf("%d rows, did not resolve %d: want 4 rows and the 57 guesses that do not exist counted (%v)", len(got), rep.Counts["did not resolve"], rep.Counts)
	}
	asked := map[string]bool{}
	for _, n := range order() {
		asked[n] = true
	}
	for _, g := range guesses {
		if !asked[g] {
			t.Errorf("%s was not looked up: with -live the guesses are looked up by default", g)
		}
	}
	if _, _, code := runContract(t, "subs", "-d", "example.org", "-live", "-guesses", "-no-history"); code != exitUsage {
		t.Errorf("-live -guesses: exit %d, want %d", code, exitUsage)
	}
}

// -exclude-sources subdomaincenter does not ask the source: none of its
// guesses is looked up, where without it every one is.
func TestSubsExcludeSourcesDoesNotAskSubdomainCenter(t *testing.T) {
	var guesses []string
	for i := 0; i < 30; i++ {
		guesses = append(guesses, fmt.Sprintf("g%02d.example.org", i))
	}
	for _, exclude := range []bool{false, true} {
		t.Run(fmt.Sprint("exclude=", exclude), func(t *testing.T) {
			resolver, order := orderResolver(t, "n0.example.org")
			defer subcol.UseTestSources(
				subcol.TestSource{Name: "s", Default: true, Names: []string{"n0.example.org"}},
				subcol.TestSource{Name: "subdomaincenter", Default: true, Sampled: true, Padding: true, Names: guesses},
			)()
			t.Chdir(t.TempDir())
			args := []string{"subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-guess-samples", "1"}
			if exclude {
				args = append(args, "-exclude-sources", "subdomaincenter")
			}
			_, rep, code := runContract(t, args...)
			if code != exitOK {
				t.Fatalf("exit %d, notes %v", code, rep.Notes)
			}
			n := 0
			for _, q := range order() {
				if strings.HasPrefix(q, "g") {
					n++
				}
			}
			if want := map[bool]int{false: len(guesses), true: 0}[exclude]; n != want {
				t.Errorf("exclude=%v: %d guesses reached the resolver, want %d (counts %v)", exclude, n, want, rep.Counts)
			}
		})
	}
}

// A stopped -live run, as stoppedSubsWorld has it, keeps what DNS answered:
// the guesses that resolved are printed, the ones that did not are counted
// in did not resolve, and with the ones it left they are the guesses given.
func TestSubsStoppedRunPrintsTheGuessesItAnsweredAndCountsTheOthers(t *testing.T) {
	_, rep, out := stoppedSubsWorld(t)
	c := rep.Counts
	printed := 0 // guesses that resolved
	for _, l := range lines(out) {
		if strings.Contains(l, `"source":"center"`) {
			printed++
		}
	}
	// The 20 names the source gave all exist: each is printed or not asked, so
	// what did not resolve, and what was not checked, are guesses.
	if printed == 0 || rep.Results < printed || rep.Results != c["DNS-confirmed"] || rep.Results-printed+c["not asked"] != 20 {
		t.Fatalf("%d guesses printed, %d rows, counts %v", printed, rep.Results, c)
	}
	if c["did not resolve"] == 0 || c["not checked"] == 0 {
		t.Errorf("counts %v: the run answered some guesses that do not exist and left others", c)
	}
	if got := printed + c["did not resolve"] + c["not checked"]; got != 300 {
		t.Errorf("%d printed + %d did not resolve + %d not checked = %d, the guesses are 300", printed, c["did not resolve"], c["not checked"], got)
	}
}

// reproofWorld is a -live run in w.db that -max-time stops with guesses
// unchecked. subdomain.center gives a second sample, x0-x4, which exist in
// DNS, to the call that asks for one; the source "slow" (when slow is set)
// answers after 4 s, and -max-time 2s cuts it short.
func reproofWorld(t *testing.T, slow bool) (args []string) {
	t.Helper()
	var names, guesses []string
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("n%02d.example.org", i))
	}
	for i := 0; i < 300; i++ {
		guesses = append(guesses, fmt.Sprintf("g%03d.example.org", i))
	}
	later := []string{"x0.example.org", "x1.example.org", "x2.example.org", "x3.example.org", "x4.example.org"}
	real := append(append([]string{}, names...), guesses[:3]...)
	real = append(real, later...)
	real = append(real, "slow.example.org")
	resolver, _ := slowResolver(t, 0, real...)
	srcs := []subcol.TestSource{
		{Name: "s", Default: true, Names: names},
		{Name: "center", Default: true, Sampled: true, Padding: true, Rounds: [][]string{guesses, later}},
	}
	if slow {
		srcs = append(srcs, subcol.TestSource{Name: "slow", Default: true, Names: []string{"slow.example.org"}, Delay: 4 * time.Second})
	}
	t.Cleanup(subcol.UseTestSources(srcs...))
	t.Chdir(t.TempDir())
	args = []string{"subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-db", "w.db"}
	_, rep, code := runContract(t, append(append([]string{}, args...), "-dns-rate", "40", "-max-time", "2s")...)
	if code != exitLimit || rep.Counts["not checked"]+rep.Counts["not asked"] == 0 {
		t.Fatalf("the first run must stop with names unchecked: exit %d, counts %v", code, rep.Counts)
	}
	return args
}

// The next subs on the workspace continues the stopped run only for the same
// domains, collectors and -live/-w: no -live, or a -w the stopped run did not
// have, is a run of its own, which asks the sources.
func TestSubsStoppedRunIsContinuedOnlyByTheSameOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   func(args []string, t *testing.T) []string
		resume bool
	}{
		{"the same options", func(a []string, _ *testing.T) []string { return a }, true},
		{"no -live", func(a []string, _ *testing.T) []string {
			var out []string
			for _, x := range a {
				if x != "-live" {
					out = append(out, x)
				}
			}
			return out
		}, false},
		{"another -permute", func(a []string, _ *testing.T) []string { return append(append([]string{}, a...), "-permute") }, false},
		{"another -w", func(a []string, t *testing.T) []string {
			return append(append([]string{}, a...), "-w", wlist(t, "extra1"))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args(reproofWorld(t, false), t)
			_, rep, code := runContract(t, append(args, "-dns-rate", "0")...)
			if code != exitOK {
				t.Fatalf("exit %d, notes %v", code, rep.Notes)
			}
			said := strings.Contains(strings.Join(rep.Notes, "\n"), "continued the stopped run in w.db")
			if said != tc.resume {
				t.Errorf("continued=%v, want %v: %v", said, tc.resume, rep.Notes)
			}
		})
	}
}

// A continued run does not ask subdomain.center for more samples: the guesses
// the stopped run held are the ones checked, where -fresh asks again and gets
// the second sample.
func TestSubsContinuedRunDoesNotAskForMoreSamples(t *testing.T) {
	args := reproofWorld(t, false)
	out, rep, code := runContract(t, append(append([]string{}, args...), "-dns-rate", "0")...)
	if code != exitOK || !strings.Contains(strings.Join(rep.Notes, "\n"), "continued the stopped run") {
		t.Fatalf("exit %d, notes %v", code, rep.Notes)
	}
	if strings.Contains(out, "x0.example.org") {
		t.Errorf("the continued run took a second sample:\n%s", out)
	}
	if !strings.Contains(out, "g299.example.org") && !strings.Contains(out, "g002.example.org") {
		t.Errorf("the continued run did not check the guesses of the stopped one")
	}
	out, _, _ = runContract(t, append(append([]string{}, args...), "-dns-rate", "0", "-fresh")...)
	if !strings.Contains(out, "x0.example.org") {
		t.Errorf("-fresh did not take the second sample, so the test cannot tell:\n%s", out)
	}
}

// A run whose sources were cut short by -max-time is not continued: the next
// run asks the sources and gets the name the slow one gives.
func TestSubsRunWithASourceCutShortIsNotContinued(t *testing.T) {
	args := reproofWorld(t, true)
	out, rep, code := runContract(t, append(append([]string{}, args...), "-dns-rate", "0", "-max-time", "30s")...)
	if code != exitOK {
		t.Fatalf("exit %d, notes %v", code, rep.Notes)
	}
	if strings.Contains(strings.Join(rep.Notes, "\n"), "continued the stopped run") {
		t.Errorf("a run whose source was cut short was continued: %v", rep.Notes)
	}
	if !strings.Contains(out, "slow.example.org") {
		t.Errorf("the sources were not asked again:\n%s", out)
	}
}

// A history is shared between workspaces only when one directory is named,
// and nothing is written under the home or XDG directories.
func TestSubsHistoryIsNotSharedBetweenWorkspacesUnlessOneDirectoryIsNamed(t *testing.T) {
	outside, work := isolate(t)
	resolverless := func(names ...string) func() {
		return subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: names}, subcol.TestSource{Name: "history", Default: true})
	}
	var dirs [2]string
	for i, d := range []string{"a", "b"} {
		dirs[i] = filepath.Join(work, d)
		if err := os.Mkdir(dirs[i], 0o755); err != nil {
			t.Fatal(err)
		}
	}
	subs := func(db string, extra ...string) string {
		t.Helper()
		out, errOut, err := captureBoth(t, func() error {
			return run(append([]string{"subs", "-d", "example.org", "-json", "-db", filepath.Join(db, "w.db")}, extra...))
		})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return out
	}
	restore := resolverless("only-a.example.org")
	subs(dirs[0])
	restore()
	restore = resolverless("only-b.example.org")
	out := subs(dirs[1])
	restore()
	if strings.Contains(out, "only-a.example.org") {
		t.Errorf("workspace b read the history of workspace a:\n%s", out)
	}
	shared := t.TempDir()
	restore = resolverless("only-a.example.org")
	subs(dirs[0], "-history-dir", shared)
	restore()
	restore = resolverless("only-b.example.org")
	out = subs(dirs[1], "-history-dir", shared)
	restore()
	if !strings.Contains(out, "only-a.example.org") {
		t.Errorf("workspaces that name one history directory do not share it:\n%s", out)
	}
	for _, d := range outside {
		if f := filesUnder(d); len(f) != 0 {
			t.Errorf("%s was written to: %v", d, f)
		}
	}
}

// Without the guesses, subs -live asks one query a name the sources gave, as
// dnsx does at the same rate, so it takes the time dnsx takes (the queries
// over the rate), and it lists the names that exist.
func TestSubsLiveWithoutGuessesAsksAsDnsxDoesAndFindsTheSameNames(t *testing.T) {
	t.Chdir(t.TempDir())
	real, guesses, a := vulnwebShaped()
	z := &countingZone{a: a, byType: map[string]int{}, byName: map[string]int{}}
	resolvers := serveCounting(t, z, 1)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: real},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Names: guesses},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-guesses=false", "-resolvers", resolvers, "-dns-rate", "1000", "-no-history")
	if code != exitOK {
		t.Fatalf("exit %d %+v", code, rep)
	}
	want := 0
	for _, n := range real {
		if _, ok := a[n]; ok {
			want++
		}
	}
	if got := hosts(t, out); len(got) != want || want == 0 {
		t.Errorf("%d names listed, %d of the %d the sources gave exist: %v", len(got), want, len(real), got)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	for n := range z.byName {
		if strings.HasPrefix(n, "g") {
			t.Errorf("%s was looked up: no guess is asked", n)
		}
	}
	t.Logf("%d queries for %d names, by type %v", z.total.Load(), len(real), z.byType)
	if q := int(z.total.Load()); q > len(real)*105/100 {
		t.Errorf("%d queries for %d names: dnsx asks one a name", q, len(real))
	}
}

// azhaq resume of a stopped subs run does not ask the sources again and
// prints the map's rows (entities with a type and a key), not subs's own.
func TestResumeOfAStoppedSubsRunPrintsTheMapRowsAndKeepsTheSources(t *testing.T) {
	stoppedSubsWorld(t)
	out, rep, code := runContract(t, "resume", "-db", "w.db", "-dns-rate", "0")
	if code != exitOK {
		t.Fatalf("exit %d, notes %v", code, rep.Notes)
	}
	if strings.Contains(out, "late.example.org") {
		t.Errorf("the sources were asked again:\n%s", out)
	}
	rows := jsonRows(t, out)
	for _, r := range rows {
		if r["type"] != "Domain" && r["type"] != "Hostname" && r["type"] != "IPAddress" || r["key"] == nil {
			t.Errorf("row %v is not a row of the map", r)
		}
	}
	if !strings.Contains(out, `"key":"g299.example.org"`) || !strings.Contains(out, `"key":"n19.example.org"`) || len(rows) != rep.Results {
		t.Errorf("%d rows of %d results; g299 or n19 missing:\n%s", len(rows), rep.Results, out)
	}
}

// What a stopped -live run did not check is kept in the workspace: query
// -role unresolved lists it (the guesses and the names the sources gave that
// DNS was not asked about), every name listed is in the azhaq-subdomains
// payload, and the guesses among them are in its guesses list: in its
// unverified list too when no lookup reached them (the summary's not checked),
// and not when the guess check saw them resolve and DNS had not recorded them
// yet (its not asked). Whatever the timing, the two agree.
func TestSubsStoppedRunKeepsTheUncheckedNamesInTheWorkspace(t *testing.T) {
	_, rep, _ := stoppedSubsWorld(t)
	st, err := store.OpenExisting("w.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runs, _ := st.Runs()
	st.UseRun(runs[len(runs)-1].ID)
	p := payloads(st, "azhaq-subdomains")[0]
	unverified, guessList, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, n := range strs(p["unverified"]) {
		unverified[n] = true
	}
	for _, n := range strs(p["guesses"]) {
		guessList[n] = true
	}
	for _, n := range strs(p["names"]) {
		names[n] = true
	}
	out, _, _ := runContract(t, "query", "-db", "w.db", "-type", "Hostname", "-role", "unresolved")
	listed, guesses, guessesAsked := 0, 0, 0
	for _, r := range jsonRows(t, out) {
		listed++
		key, _ := r["key"].(string)
		if !names[key] {
			t.Errorf("query lists %s as unresolved and the payload does not hold it", key)
		}
		if strings.HasPrefix(key, "g") {
			if !guessList[key] {
				t.Errorf("the guess %s is unresolved and not in the payload's guesses list", key)
			}
			if unverified[key] {
				guesses++
			} else {
				guessesAsked++
			}
		}
	}
	// Not checked is the unverified names no lookup answered; the guesses
	// among them are the payload's unverified guesses, none more or less.
	if left := rep.Counts["not checked"] + rep.Counts["not asked"]; listed == 0 || listed != left || guesses != rep.Counts["not checked"] || guessesAsked > rep.Counts["not asked"] {
		t.Errorf("query lists %d names (%d unverified guesses, %d resolved ones), the run left %d (counts %v)", listed, guesses, guessesAsked, left, rep.Counts)
	}
}
