package main

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// A line that starts with # is a word like any other, as in ffuf, unless -ic
// is given: dirs, run -dirs and fuzz.
func TestCommentLinesAreWordsUnlessIC(t *testing.T) {
	words := wlist(t, "#top", "about", "# note", "users/v1 # tail")
	count := func(app *sweepApp, line string) int { return app.count(line) }
	dirs := func(flags ...string) *sweepApp {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"dirs", "-u", app.srv.URL, "-w", words, "-json", "-db", sweepDB(t), "-ledger", "off"}, flags...)
		if _, errOut, code := cli(t, args...); code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		return app
	}
	app := dirs()
	for _, line := range []string{"GET /#top", "GET /# note", "GET /users/v1 # tail"} {
		if count(app, line) != 1 {
			t.Errorf("dirs without -ic: %q was asked %d times: %v", line, count(app, line), app.got)
		}
	}
	app = dirs("-ic")
	for _, line := range []string{"GET /#top", "GET /# note"} {
		if count(app, line) != 0 {
			t.Errorf("dirs -ic: %q was asked: %v", line, app.got)
		}
	}
	if count(app, "GET /users/v1") != 1 || count(app, "GET /about") != 1 {
		t.Errorf("dirs -ic: the words and a word with a note were not asked: %v", app.got)
	}

	runDirs := func(flags ...string) *sweepApp {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"run", "-url", app.srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-depth", "1",
			"-dirs", words, "-db", sweepDB(t), "-ledger", "off", "-json"}, flags...)
		if _, errOut, err := captureBoth(t, func() error { return run(args) }); err != nil {
			t.Fatalf("%v: %s", err, errOut)
		}
		return app
	}
	if app = runDirs(); count(app, "GET /#top") != 1 {
		t.Errorf("run -dirs without -dirs-ic did not ask #top: %v", app.got)
	}
	if app = runDirs("-dirs-ic"); count(app, "GET /#top") != 0 || count(app, "GET /about") != 1 {
		t.Errorf("run -dirs -dirs-ic: %v", app.got)
	}

	fz := func(flags ...string) *sweepApp {
		app := newSweepApp(t)
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"-u", app.srv.URL + "/FUZZ", "-w", words, "-mc", "all", "-db", sweepDB(t), "-ledger", "off", "-json"}, flags...)
		_, _, _ = captureBoth(t, func() error { return cmdFuzz(args) })
		return app
	}
	// A # starts a fragment in a URL, so the request is for /: count the requests.
	if app = fz(); app.total() != 4 {
		t.Errorf("fuzz without -ic sent %d requests for 4 words: %v", app.total(), app.got)
	}
	if app = fz("-ic"); app.total() != 2 || count(app, "GET /about") != 1 {
		t.Errorf("fuzz -ic sent %d requests for 2 words: %v", app.total(), app.got)
	}
}
