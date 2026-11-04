package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/store"
)

// stoppedSubsWorld is a -live run that -max-time stops with some of the
// guesses unchecked, in the workspace w.db: 20 names the sources assert, 300
// guesses of which g000-g002 and g295-g299 exist, and a source that gives
// late.example.org only when it is asked a second time.
func stoppedSubsWorld(t *testing.T) (args []string, first report, firstOut string) {
	t.Helper()
	var names, guesses []string
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("n%02d.example.org", i))
	}
	for i := 0; i < 300; i++ {
		guesses = append(guesses, fmt.Sprintf("g%03d.example.org", i))
	}
	real := append(append([]string{}, names...), guesses[:3]...)
	real = append(real, guesses[295:]...)
	real = append(real, "late.example.org")
	resolver, _ := slowResolver(t, 0, real...)
	t.Cleanup(subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Rounds: [][]string{names, append(append([]string{}, names...), "late.example.org")}},
		subcol.TestSource{Name: "center", Default: true, Sampled: true, Padding: true, Names: guesses},
	))
	t.Chdir(t.TempDir())
	args = []string{"subs", "-d", "example.org", "-live", "-resolvers", resolver, "-no-history", "-db", "w.db"}
	out, rep, code := runContract(t, append(append([]string{}, args...), "-dns-rate", "40", "-max-time", "3s")...)
	if code != exitLimit || rep.Counts["not checked"] == 0 {
		t.Fatalf("the first run must stop with guesses unchecked: exit %d, counts %v", code, rep.Counts)
	}
	return args, rep, out
}

// A stopped run's unchecked names stay in the workspace: the next run on it
// checks them, does not ask the sources again, and says so with the number
// of names it checked, which is what the stopped run left.
func TestSubsStoppedRunResumesFromItsWorkspaceWithoutAskingSources(t *testing.T) {
	args, first, firstOut := stoppedSubsWorld(t)
	left := first.Counts["not checked"] + first.Counts["not asked"]
	out, rep, code := runContract(t, append(append([]string{}, args...), "-dns-rate", "0")...)
	if code != exitOK {
		t.Fatalf("the second run: exit %d, stopped %q, failed %+v, notes %v\n%s", code, rep.Stopped, rep.Failed, rep.Notes, out)
	}
	if strings.Contains(out, "late.example.org") {
		t.Errorf("the sources were asked again: late.example.org is a name only a second call gives\n%s", out)
	}
	for _, want := range []string{"g000.example.org", "g299.example.org", "n19.example.org"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s is missing from the resumed run's rows", want)
		}
	}
	if len(lines(out)) <= len(lines(firstOut)) {
		t.Errorf("the resumed run lists %d names, the stopped one %d", len(lines(out)), len(lines(firstOut)))
	}
	notes := strings.Join(rep.Notes, "\n")
	want := fmt.Sprintf("continued the stopped run in w.db: %d names had no DNS answer yet and were asked; the sources were not asked again", left)
	if !strings.Contains(notes, want) {
		t.Errorf("the summary does not say it: want %q in\n%s", want, notes)
	}
	if rep.Counts["not checked"] != 0 || rep.Counts["not asked"] != 0 {
		t.Errorf("counts %v: nothing is left unchecked", rep.Counts)
	}
	if rep.Counts["from sources"] != first.Counts["from sources"] {
		t.Errorf("from sources %d, the stopped run had %d", rep.Counts["from sources"], first.Counts["from sources"])
	}
}

// -fresh asks the sources again, as a run on a new workspace does.
func TestSubsFreshAsksTheSourcesAgainInAWorkspaceWithAStoppedRun(t *testing.T) {
	args, _, _ := stoppedSubsWorld(t)
	out, rep, _ := runContract(t, append(append([]string{}, args...), "-dns-rate", "0", "-fresh")...)
	if !strings.Contains(out, "late.example.org") {
		t.Errorf("-fresh did not ask the sources again:\n%s", out)
	}
	if strings.Contains(strings.Join(rep.Notes, "\n"), "continued the stopped run") {
		t.Errorf("-fresh says it continued a run: %v", rep.Notes)
	}
}

// azhaq resume continues a stopped subs run the same way: the sources that
// answered are not asked again.
func TestResumeOfAStoppedSubsRunDoesNotAskTheSourcesAgain(t *testing.T) {
	args, _, _ := stoppedSubsWorld(t)
	_ = args
	_, rep, code := runContract(t, "resume", "-db", "w.db", "-dns-rate", "0")
	if code != exitOK {
		t.Fatalf("resume: exit %d, failed %+v, notes %v", code, rep.Failed, rep.Notes)
	}
	out, _, _ := runContract(t, "query", "-db", "w.db", "-type", "Hostname")
	if strings.Contains(out, "late.example.org") {
		t.Errorf("the resume asked the sources again: late.example.org is a name only a second call gives")
	}
	if !strings.Contains(out, "g299.example.org") {
		t.Errorf("the resume did not check the guesses the stopped run left")
	}
}

// A stopped run says what its estimate of the names left unchecked rests on,
// and labels it an estimate. The names looked up are the guesses the check
// answered: they and the ones it left add up to the guesses given, and the
// share that resolved is the one the note says.
func TestSubsStoppedRunLabelsItsEstimateOfTheUncheckedNames(t *testing.T) {
	_, rep, _ := stoppedSubsWorld(t)
	st, err := store.OpenExisting("w.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runs, _ := st.Runs()
	st.UseRun(runs[len(runs)-1].ID)
	ps := payloads(st, "azhaq-subdomains")
	row, _ := ps[0]["sources"].(map[string]any)["center"].(map[string]any)
	kept, dropped, left := intOf(row["kept"]), intOf(row["dropped_unresolved"]), intOf(row["unverified"])
	if kept+dropped+left != 300 || dropped == 0 {
		t.Fatalf("the 300 guesses are not accounted for: %d resolved, %d did not, %d left, %v", kept, dropped, left, row)
	}
	lookedUp, unchecked := kept+dropped, rep.Counts["not checked"]
	want := fmt.Sprintf("estimate, not a count: of the %d names looked up that only subdomain.center or the name history held, %d resolved; the %d left unchecked are of the same kind, so about %d of them would resolve if that share held (a sample of %d names)",
		lookedUp, kept, unchecked, (unchecked*kept+lookedUp/2)/lookedUp, lookedUp)
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, want) {
		t.Errorf("want %q in\n%s", want, notes)
	}
	if !strings.Contains(notes, fmt.Sprintf("the %d names only center held were looked up in DNS in", lookedUp)) {
		t.Errorf("the look-up note does not say %d names:\n%s", lookedUp, notes)
	}
}
