package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// heldApp has a page that reaches one GET of each kind by a link, a script's
// route, a GET form and a POST form, some under a name that declares a state
// change and some under one that does not, and counts every request as
// "METHOD /path".
type heldApp struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []string
}

func newHeldApp(t *testing.T) *heldApp {
	t.Helper()
	a := &heldApp{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		a.mu.Lock()
		a.got = append(a.got, r.Method+" "+r.URL.Path)
		a.mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>app</title><script src="/app.js"></script>
<a href="/flush">flush</a> <a href="/user/delete?id=1">delete</a>
<form method="get" action="/search"><input name="q" type="text"></form>
<form method="get" action="/reset-form"><input name="q" type="text"></form>
<form method="post" action="/remove-item"><input name="id" type="text"></form>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/list"); fetch("/api/purge-cache");`)
		case "/flush", "/user/delete", "/search", "/reset-form", "/remove-item", "/api/list", "/api/purge-cache", "/logout", "/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *heldApp) count(line string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, g := range a.got {
		if g == line {
			n++
		}
	}
	return n
}

func (a *heldApp) runWith(t *testing.T, flags ...string) (report, string) {
	t.Helper()
	egress.Reset()
	t.Cleanup(egress.Reset)
	args := append([]string{"run", "-url", a.srv.URL + "/", "-sources", "none", "-quiet", "-json", "-db", filepath.Join(t.TempDir(), "w.db"), "-ledger", "off"}, flags...)
	_, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	return lastReport(t, errOut), errOut
}

// A GET found in a link, a script, an API description or a GET form is
// requested under any name that declares nothing, and held back under one
// that does (/user/delete in a link, /api/purge-cache in a script,
// /reset-form as a form's action): not sent, listed as skipped with the flag
// that sends it, and counted. With the flag every one is sent.
func TestRunHoldsAFoundGETOfEveryKindThatDeclaresAStateChange(t *testing.T) {
	app := newHeldApp(t)
	rep, _ := app.runWith(t, "-fill-forms")
	for _, p := range []string{"GET /flush", "GET /api/list", "GET /search"} {
		if app.count(p) == 0 {
			t.Errorf("%s declares nothing and was not requested: %v", p, app.got)
		}
	}
	held := []string{"/user/delete", "/api/purge-cache", "/reset-form"}
	for _, p := range held {
		if n := app.count("GET " + p); n != 0 {
			t.Errorf("GET %s declares a state change and was sent %d times", p, n)
		}
		found := false
		for _, s := range rep.Skipped {
			if strings.HasPrefix(urlPath(s.Target), p) && strings.Contains(s.Reason, "-send-state-changing") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not listed as skipped with the flag: %+v", p, rep.Skipped)
		}
	}
	if rep.StateChangingHeld != len(held) {
		t.Errorf("state_changing_held %d, want %d", rep.StateChangingHeld, len(held))
	}
	if app.count("POST /remove-item") != 0 {
		t.Errorf("a POST form was sent without -submit-forms")
	}

	// With the flag, each of them is sent.
	app2 := newHeldApp(t)
	rep2, _ := app2.runWith(t, "-fill-forms", "-send-state-changing")
	for _, p := range held {
		if app2.count("GET "+p) == 0 {
			t.Errorf("-send-state-changing: GET %s was not sent", p)
		}
	}
	if rep2.StateChangingHeld != 0 {
		t.Errorf("-send-state-changing: %d held", rep2.StateChangingHeld)
	}
}

// What the user chose by a flag is not held back: a write named by its flag
// is sent, and a -deny-path rule that covers the URL stays a deny, listed
// under the rule. (A word of a wordlist is held like a link: see
// TestRunDirsFileHoldsAListedWordThatNamesAnAction.)
func TestRunDoesNotHoldAWriteAskedForByItsFlag(t *testing.T) {
	// A POST form whose action declares a state change, with -submit-forms.
	app := newHeldApp(t)
	app.runWith(t, "-submit-forms")
	if app.count("POST /remove-item") == 0 {
		t.Errorf("a write asked for with -submit-forms was held back: %v", app.got)
	}

	// A -deny-path rule keeps a held-name URL out as a deny, listed under the rule.
	app4 := newHeldApp(t)
	rep4, _ := app4.runWith(t, "-deny-path", `^/user/delete`)
	if app4.count("GET /user/delete") != 0 {
		t.Errorf("a denied URL was sent")
	}
	if len(skippedFor(rep4, "-deny-path ^/user/delete")) == 0 && !skippedUnder(rep4, "^/user/delete") {
		t.Errorf("the denied URL is not listed under its rule: %+v", rep4.Skipped)
	}
	for _, e := range rep4.StateChanging {
		if strings.HasPrefix(urlPath(e.URL), "/user/delete") {
			t.Errorf("a URL a -deny-path rule covers is listed as held back: %+v", e)
		}
	}
}

// skippedUnder says some skipped entry names the rule in its reason.
func skippedUnder(rep report, rule string) bool {
	for _, s := range rep.Skipped {
		if strings.Contains(s.Reason, rule) && strings.Contains(urlPath(s.Target), "/user/delete") {
			return true
		}
	}
	return false
}

// Each entry of the summary's state_changing names the -deny-path rule that
// keeps it out: a second run with exactly that rule sends no request for the
// URL and lists it under the rule instead.
func TestRunStateChangingEntriesNameTheRuleThatKeepsThemOut(t *testing.T) {
	app := newStateApp(t)
	rep, _ := runState(t, app)
	if len(rep.StateChanging) == 0 {
		t.Fatal("no entry to follow")
	}
	for _, e := range rep.StateChanging {
		if rule, ok := strings.CutPrefix(e.DenyPath, "-deny-path "); !ok || rule == "" {
			t.Fatalf("%s: deny_path %q does not name a rule", e.URL, e.DenyPath)
		}
	}
	// Send everything, but keep each URL out by the rule its entry names.
	for _, e := range rep.StateChanging {
		app2 := newStateApp(t)
		rule := strings.TrimPrefix(e.DenyPath, "-deny-path ")
		rep2, _ := runState(t, app2, "-send-state-changing", "-deny-path", rule)
		p := urlPath(e.URL)
		if n := app2.count("GET " + p); n != 0 {
			t.Errorf("with %s, GET %s was sent %d times", e.DenyPath, p, n)
		}
		listed := false
		for _, s := range rep2.Skipped {
			if urlPath(s.Target) == p && strings.Contains(s.Reason, rule) {
				listed = true
			}
		}
		if !listed {
			t.Errorf("with %s, %s is not listed under the rule: %+v", e.DenyPath, p, rep2.Skipped)
		}
		for _, e2 := range rep2.StateChanging {
			if urlPath(e2.URL) == p {
				t.Errorf("a URL the rule keeps out is still an entry: %+v", e2)
			}
		}
	}
}

// A target the user gave is named in the first lines of the run's stderr
// before anything else, and every entry has a status: a plan says "given as
// a target", a run that sent it "sent", and one that found a URL and sent no
// request for it "not requested".
func TestRunNamesTheStateChangingTargetFirstAndSaysWhatBecameOfEach(t *testing.T) {
	app := newStateApp(t)
	egress.Reset()
	t.Cleanup(egress.Reset)
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", app.srv.URL + "/logout", "-sources", "none", "-depth", "0", "-no-paths", "-db", filepath.Join(t.TempDir(), "w.db"), "-ledger", "off"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	first := strings.SplitN(strings.TrimSpace(errOut), "\n", 2)[0]
	if !strings.HasPrefix(first, "azhaq run: GET "+app.srv.URL+"/logout may change state") || !strings.Contains(first, "-deny-path ^/logout$") {
		t.Errorf("the first line of stderr is %q, want the target named with its rule", first)
	}

	// A plan names it as a target it would send.
	p := planJSON(t, "-url", app.srv.URL+"/logout", "-sources", "none", "-depth", "0")
	if len(p.StateChanging) != 1 || p.StateChanging[0].Status != stateGiven {
		t.Errorf("plan state_changing %+v, want one entry given as a target", p.StateChanging)
	}

	// A run that finds state-changing links past its -depth and sends no
	// request for them (nothing is held: -send-state-changing): found, and
	// no request for it.
	app2 := newStateApp(t)
	rep, _ := runState(t, app2, "-send-state-changing", "-depth", "0", "-no-paths")
	notAsked := 0
	for _, e := range rep.StateChanging {
		sent := app2.count("GET " + urlPath(e.URL))
		switch e.Status {
		case stateSent:
			if sent == 0 {
				t.Errorf("%s is said to be sent and the app saw no request", e.URL)
			}
		case stateNotAsked:
			notAsked++
			if sent != 0 {
				t.Errorf("%s is said not to be requested and the app saw %d", e.URL, sent)
			}
		default:
			t.Errorf("%s is %q: nothing was held (-send-state-changing) and nothing is given", e.URL, e.Status)
		}
	}
	if notAsked == 0 {
		t.Errorf("no entry is not requested: %+v", rep.StateChanging)
	}
}
