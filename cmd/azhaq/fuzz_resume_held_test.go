package main

import (
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// An input held back as a state-changing GET stays open: a plain resume holds
// it again, and a resume with -send-state-changing asks it, once.
func TestFuzzResumeSendsTheInputsHeldBack(t *testing.T) {
	app := newSweepApp(t)
	db := sweepDB(t)
	egress.Reset()
	t.Cleanup(egress.Reset)
	args := []string{"-u", app.srv.URL + "/FUZZ", "-w", wlist(t, "logout", "about", "reset"), "-mc", "all", "-db", db, "-ledger", "off", "-json"}
	_, errOut, err := captureBoth(t, func() error { return cmdFuzz(args) })
	if err != nil {
		t.Fatal(err)
	}
	rep := lastReport(t, errOut)
	if rep.StateChangingHeld != 2 || app.total() != 1 {
		t.Fatalf("first run: held %d, asked %v", rep.StateChangingHeld, app.got)
	}
	if len(rep.Next) == 0 || !strings.Contains(strings.Join(rep.Next, "\n"), "azhaq resume -db "+db+" -send-state-changing") {
		t.Errorf("next does not name the resume that sends them: %v", rep.Next)
	}

	egress.Reset()
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatalf("plain resume: %v", err)
	}
	if rep = lastReport(t, errOut); rep.StateChangingHeld != 2 || app.total() != 1 {
		t.Errorf("a plain resume sends nothing: held %d, asked %v", rep.StateChangingHeld, app.got)
	}

	egress.Reset()
	_, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-json", "-send-state-changing"}) })
	if err != nil {
		t.Fatalf("resume -send-state-changing: %v", err)
	}
	rep = lastReport(t, errOut)
	if app.count("GET /logout") != 1 || app.count("GET /reset") != 1 || app.count("GET /about") != 1 || rep.StateChangingHeld != 0 {
		t.Errorf("each input is asked once: held %d, asked %v", rep.StateChangingHeld, app.got)
	}
	if len(rep.Next) > 0 && strings.Contains(strings.Join(rep.Next, "\n"), "resume") {
		t.Errorf("nothing is left to resume: %v", rep.Next)
	}

	// All asked now: nothing is left.
	if err := cmdResume([]string{"-db", db, "-json"}); err == nil || !strings.Contains(err.Error(), "nothing to resume") {
		t.Errorf("a finished workspace has nothing to resume: %v", err)
	}
}

// An extension is added after a word's query (?action=stop is ?action=stop.php),
// and that input is held as the word is.
func TestFuzzHoldsAWordWithItsExtension(t *testing.T) {
	app := newSweepApp(t)
	egress.Reset()
	t.Cleanup(egress.Reset)
	args := []string{"-u", app.srv.URL + "/FUZZ", "-w", wlist(t, "console?action=stop", "console?action=view"), "-e", ".php", "-mc", "all", "-db", sweepDB(t), "-ledger", "off", "-json"}
	_, errOut, _ := captureBoth(t, func() error { return cmdFuzz(args) })
	rep := lastReport(t, errOut)
	if rep.StateChangingHeld != 2 || app.total() != 2 {
		t.Errorf("held %d, asked %v", rep.StateChangingHeld, app.got)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "2 of the 4 words of the FUZZ wordlist") {
		t.Errorf("the note counts the extension forms: %v", rep.Notes)
	}
}
