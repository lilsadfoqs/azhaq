package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// A list of the user's holds words that name an action, as a path (logout,
// reset) or in the query (console?action=stop), and words that do not.
var heldList = []string{"logout", "users/v1", "reset", "console?action=stop", "about"}

// checkHeldRows holds a run of a list to the issue's terms: the held words
// are not sent, each is a row (skipped, and state_changing with the status
// held back), the counts add up, and a note names how many and the flag.
func checkHeldRows(t *testing.T, app *sweepApp, rep report, want []string, note string) {
	t.Helper()
	for _, w := range want {
		if n := app.count("GET /" + w); n != 0 {
			t.Errorf("GET /%s names a state change and was sent %d times", w, n)
		}
		skipped := 0
		for _, s := range rep.Skipped {
			if strings.HasSuffix(s.Target, "/"+w) && strings.Contains(s.Reason, "-send-state-changing") {
				skipped++
			}
		}
		if skipped != 1 {
			t.Errorf("/%s is listed %d times under skipped with the flag, want once", w, skipped)
		}
		rows := 0
		for _, e := range rep.StateChanging {
			if strings.HasSuffix(e.URL, "/"+w) && e.Status == stateHeld && e.Send == "-send-state-changing" {
				rows++
			}
		}
		if rows != 1 {
			t.Errorf("/%s is %d held rows of state_changing, want 1", w, rows)
		}
	}
	if rep.StateChangingHeld != len(want) {
		t.Errorf("state_changing_held = %d, want %d", rep.StateChangingHeld, len(want))
	}
	if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.Contains(n, note) && strings.Contains(n, "-send-state-changing") }) {
		t.Errorf("no note says %q with the flag: %q", note, rep.Notes)
	}
}

// dirs -w LIST holds the words that name an action, whatever the list: each
// is a row with the status held back, a note before the first request names
// how many and the flag, and -send-state-changing sends every word.
func TestDirsHoldsAListedWordThatNamesAnAction(t *testing.T) {
	held := []string{"logout", "reset", "console?action=stop"}
	run1 := func(flags ...string) (*sweepApp, report) {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"dirs", "-u", app.srv.URL, "-w", wlist(t, heldList...), "-json", "-db", sweepDB(t), "-ledger", "off"}, flags...)
		_, errOut, code := cli(t, args...)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		return app, lastReport(t, errOut)
	}
	app, rep := run1()
	checkHeldRows(t, app, rep, held, "-dirs: 3 of the 5 requests")
	if app.count("GET /users/v1") != 1 || app.count("GET /about") != 1 {
		t.Errorf("the other words were not asked: %v", app.got)
	}
	// Every request is a sent word or a calibration probe, the rest are held.
	if int(rep.Requests) != app.total() {
		t.Errorf("the summary says %d requests, the server saw %d", rep.Requests, app.total())
	}
	app2, rep2 := run1("-send-state-changing")
	for _, w := range []string{"/logout", "/reset", "/console?action=stop"} {
		if app2.count("GET "+w) != 1 {
			t.Errorf("-send-state-changing did not send %s: %v", w, app2.got)
		}
	}
	if len(rep2.Skipped) != 0 || rep2.StateChangingHeld != 0 {
		t.Errorf("with the flag nothing is held: %+v", rep2.Skipped)
	}
	for _, e := range rep2.StateChanging {
		if e.Status != stateSent {
			t.Errorf("with the flag %s is %s, want sent", e.URL, e.Status)
		}
	}
	for _, n := range rep2.Notes {
		if strings.Contains(n, "held back") {
			t.Errorf("with the flag a note says something is held: %s", n)
		}
	}
}

// run -dirs FILE holds the same words, the note is on stderr before the
// first request, and the flag sends them.
func TestRunDirsFileHoldsAListedWordThatNamesAnAction(t *testing.T) {
	held := []string{"logout", "reset", "console?action=stop"}
	run1 := func(flags ...string) (*sweepApp, report, string) {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"run", "-url", app.srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-depth", "1",
			"-dirs", wlist(t, heldList...), "-db", sweepDB(t), "-ledger", "off"}, flags...)
		_, errOut, err := captureBoth(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("%v: %s", err, errOut)
		}
		if slices.Contains(flags, "-json") {
			return app, lastReport(t, errOut), errOut
		}
		return app, report{}, errOut
	}
	app, rep, _ := run1("-json")
	checkHeldRows(t, app, rep, held, "-dirs: 3 of the 5 requests")
	// Without -json the note is a line of stderr, printed before the summary.
	_, _, text := run1()
	note, summary := strings.Index(text, "-dirs: 3 of the 5 requests"), strings.Index(text, "map rows")
	if note < 0 || summary < 0 || note > summary {
		t.Errorf("stderr has no line for the held words before the summary: %s", text)
	}
	app2, rep2, _ := run1("-json", "-send-state-changing")
	for _, w := range []string{"/logout", "/reset", "/console?action=stop"} {
		if app2.count("GET "+w) != 1 {
			t.Errorf("-send-state-changing did not send %s", w)
		}
	}
	if rep2.StateChangingHeld != 0 || len(rep2.Skipped) != 0 {
		t.Errorf("with the flag nothing is held: %+v", rep2.Skipped)
	}
}

// run -paths FILE holds the words that name an action in the same way.
func TestRunPathsFileHoldsAListedWordThatNamesAnAction(t *testing.T) {
	held := []string{"logout", "reset", "console?action=stop"}
	run1 := func(flags ...string) (*sweepApp, report) {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"run", "-url", app.srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-favicon", "-depth", "1",
			"-paths", wlist(t, heldList...), "-json", "-db", sweepDB(t), "-ledger", "off"}, flags...)
		_, errOut, err := captureBoth(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("%v: %s", err, errOut)
		}
		return app, lastReport(t, errOut)
	}
	app, rep := run1()
	checkHeldRows(t, app, rep, held, "-paths: 3 words of the wordlist")
	if app.count("GET /users/v1") != 1 || app.count("GET /about") != 1 {
		t.Errorf("the other words were not asked: %v", app.got)
	}
	app2, rep2 := run1("-send-state-changing")
	for _, w := range []string{"/logout", "/reset", "/console?action=stop"} {
		if app2.count("GET "+w) != 1 {
			t.Errorf("-send-state-changing did not send %s: %v", w, app2.got)
		}
	}
	if rep2.StateChangingHeld != 0 || len(rep2.Skipped) != 0 {
		t.Errorf("with the flag nothing is held: %+v", rep2.Skipped)
	}
}

// fuzz holds the inputs whose URL names an action, one row each, and the flag
// sends them; the URL the user typed is theirs.
func TestFuzzHoldsAListedWordThatNamesAnAction(t *testing.T) {
	held := []string{"logout", "reset"}
	run1 := func(flags ...string) (*sweepApp, report) {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"-u", app.srv.URL + "/FUZZ", "-w", wlist(t, "logout", "users/v1", "reset", "about"), "-mc", "all", "-db", sweepDB(t), "-ledger", "off"}, flags...)
		_, errOut, _ := captureBoth(t, func() error { return cmdFuzz(append(args, "-json")) })
		return app, lastReport(t, errOut)
	}
	app, rep := run1()
	checkHeldRows(t, app, rep, held, "2 of the 4 words of the FUZZ wordlist")
	if app.count("GET /users/v1") != 1 || app.count("GET /about") != 1 {
		t.Errorf("the other words were not asked: %v", app.got)
	}
	app2, rep2 := run1("-send-state-changing")
	if app2.count("GET /logout") != 1 || app2.count("GET /reset") != 1 {
		t.Errorf("-send-state-changing did not send the words: %v", app2.got)
	}
	if rep2.StateChangingHeld != 0 || len(rep2.Skipped) != 0 {
		t.Errorf("with the flag nothing is held: %+v", rep2.Skipped)
	}
	// A query value that names an action is held; one in another parameter is not.
	app3 := newSweepApp(t)
	egress.Reset()
	args := []string{"-u", app3.srv.URL + "/console?action=FUZZ", "-w", wlist(t, "stop", "view"), "-mc", "all", "-db", sweepDB(t), "-ledger", "off", "-json"}
	_, _, _ = captureBoth(t, func() error { return cmdFuzz(args) })
	if app3.count("GET /console?action=stop") != 0 || app3.count("GET /console?action=view") != 1 {
		t.Errorf("a query action: %v", app3.got)
	}
	// A URL that names a state change itself is the user's: every word is sent.
	app4 := newSweepApp(t)
	egress.Reset()
	args = []string{"-u", app4.srv.URL + "/logout?x=FUZZ", "-w", wlist(t, "a", "b"), "-mc", "all", "-db", sweepDB(t), "-ledger", "off", "-json"}
	_, _, _ = captureBoth(t, func() error { return cmdFuzz(args) })
	if app4.total() != 2 {
		t.Errorf("the user's own URL was held: %v", app4.got)
	}
	// A write is a request the user asked for by its method: not held.
	app5 := newSweepApp(t)
	egress.Reset()
	args = []string{"-u", app5.srv.URL + "/FUZZ", "-X", "POST", "-w", wlist(t, "logout"), "-mc", "all", "-db", sweepDB(t), "-ledger", "off", "-json"}
	_, _, _ = captureBoth(t, func() error { return cmdFuzz(args) })
	if app5.count("POST /logout") != 1 {
		t.Errorf("a POST of a word was held: %v", app5.got)
	}
}
