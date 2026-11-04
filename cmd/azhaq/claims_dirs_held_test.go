package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// With the built-in list a word whose own name declares a state change is not
// sent, with an extension too (logout.php): it is listed under skipped with
// the flag that sends it. With the flag it is sent.
func TestDirsBuiltinListHoldsAStateChangingWordAndItsExtension(t *testing.T) {
	run1 := func(flags ...string) (report, *stateApp) {
		app := newStateApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"dirs", "-u", app.srv.URL, "-e", "php", "-json", "-silent", "-db", filepath.Join(t.TempDir(), "d.db"), "-ledger", "off"}, flags...)
		_, errOut, err := captureBoth(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return lastReport(t, errOut), app
	}
	rep, app := run1()
	for _, p := range []string{"/logout", "/logout.php", "/delete", "/delete.php", "/populate", "/populate.php"} {
		if n := app.count("GET " + p); n != 0 {
			t.Errorf("the built-in word %s declares a state change and was sent %d times", p, n)
		}
		listed := false
		for _, s := range rep.Skipped {
			if urlPath(s.Target) == p && strings.Contains(s.Reason, "-send-state-changing") {
				listed = true
			}
		}
		if !listed {
			t.Errorf("%s is not listed under skipped with the flag", p)
		}
	}
	if n := len(app.asked()); n < 1000 {
		t.Errorf("the rest of the list was not asked: %d requests", n)
	}
	rep2, app2 := run1("-send-state-changing")
	if app2.count("GET /logout.php") == 0 || app2.count("GET /logout") == 0 {
		t.Errorf("-send-state-changing did not send the held words")
	}
	for _, s := range rep2.Skipped {
		if strings.Contains(s.Reason, "-send-state-changing") {
			t.Errorf("with the flag a word is still held: %+v", s)
		}
	}
}

// A directory two hits are found in costs one more request than the plan
// counts: the plan says it is a floor (at least) and names that request, and
// the run sent that estimate plus one control for the directory.
func TestDirsEstimateIsAFloorThatNamesTheControlOfADirectory(t *testing.T) {
	srv := foldSPA(t, nil)
	wl := wlist(t, strings.Fields(foldWords)...)
	args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-depth", "1", "-dirs", wl}
	out, _, _ := cli(t, append([]string{"plan", "-json"}, args...)...)
	plan := planStageRequests(t, out, "dirs")
	stage := map[string]any{}
	var planned map[string]any
	if err := json.Unmarshal([]byte(out), &planned); err != nil {
		t.Fatal(err)
	}
	for _, s := range planned["estimate"].(map[string]any)["stages"].([]any) {
		if st := s.(map[string]any); st["stage"] == "dirs" {
			stage = st
		}
	}
	if stage["estimate_at_least"] != true || !strings.Contains(stage["not_counted"].(string), "a directory two hits are found in") || !strings.Contains(stage["not_counted"].(string), "one more request") {
		t.Errorf("the plan does not call the dirs estimate a floor that names the control: %v", stage)
	}
	sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
	got := stageAmount(stagesOf(t, sum)["dirs"], "actual", "requests")
	// /api/ and /priv/ each hold two hits or more: one control each.
	if got != plan+2 {
		t.Errorf("the plan counts %v dirs requests, the run sent %v: want the plan plus the 2 controls", plan, got)
	}
}
