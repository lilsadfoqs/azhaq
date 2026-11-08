package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/urlcol"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
)

// stateApp is shaped like VAmPI: its home page names the app's own creation in
// prose, its API description lists GET /createdb, and its pages link a logout,
// a delete and a reset. It counts every request by "METHOD path".
type stateApp struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []string
}

func newStateApp(t *testing.T) *stateApp {
	t.Helper()
	a := &stateApp{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.got = append(a.got, r.Method+" "+r.URL.Path)
		a.mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>VAmPI</title><a href="/openapi.json">spec</a> <a href="/logout.php">out</a> <a href="/user/delete?id=1">del</a> <a href="/reset">reset</a> <a href="/users/v1">users</a>`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.1","info":{"title":"VAmPI","version":"1","description":"VAmPI was created to be vulnerable"},"paths":{`+
				`"/":{"get":{"operationId":"home","summary":"VAmPI home","description":"VAmPI was created as a vulnerable API"}},`+
				`"/createdb":{"get":{"summary":"Creates and populates the database"}},`+
				`"/users/v1":{"get":{"summary":"List users"}}}}`)
		case "/users/v1", "/createdb", "/logout.php", "/user/delete", "/reset", "/logout":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *stateApp) asked() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.got)
}

func (a *stateApp) count(line string) int {
	n := 0
	for _, g := range a.asked() {
		if g == line {
			n++
		}
	}
	return n
}

// urlPath is the path of a URL, its query left out.
func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Path
}

// declared are the GETs of the app whose own path or operation names a
// state change.
var declared = []string{"/createdb", "/logout.php", "/user/delete", "/reset"}

func runState(t *testing.T, a *stateApp, flags ...string) (report, string) {
	t.Helper()
	egress.Reset()
	t.Cleanup(egress.Reset)
	args := append([]string{"run", "-url", a.srv.URL + "/", "-sources", "none", "-quiet", "-json", "-db", filepath.Join(t.TempDir(), "w.db")}, flags...)
	_, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	return lastReport(t, errOut), errOut
}

// ledgerGETs are the GET lines to targets that the ledger holds, as paths.
func ledgerGETs(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.IsTarget() && (e.Kind == "http" || e.Kind == "chrome") && (e.Method == "GET" || e.Method == "") {
			if u, err := url.Parse(e.Target); err == nil {
				out = append(out, u.Path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// A GET found on the way whose own path or operation declares a state change
// is not sent: no request reaches the app for it, the summary lists it as
// held back with the flag that sends it, and the home page, whose
// description only says the app "was created", is not named at all.
func TestFoundStateChangingGETsAreHeldBack(t *testing.T) {
	app := newStateApp(t)
	rep, errOut := runState(t, app)
	for _, p := range declared {
		if n := app.count("GET " + p); n != 0 {
			t.Errorf("GET %s was sent %d times", p, n)
		}
	}
	for _, p := range []string{"/", "/openapi.json", "/users/v1"} {
		if app.count("GET "+p) == 0 {
			t.Errorf("GET %s, which declares nothing, was not sent: %v", p, app.asked())
		}
	}
	if rep.StateChangingHeld != len(declared) {
		t.Errorf("state_changing_held %d, want %d\n%s", rep.StateChangingHeld, len(declared), errOut)
	}
	held := map[string]bool{}
	for _, e := range rep.StateChanging {
		if strings.HasSuffix(e.URL, "/") && strings.Count(e.URL, "/") == 3 {
			t.Errorf("the home page is labelled as changing state: %+v", e)
		}
		if e.Status != stateHeld || e.Send != "-send-state-changing" {
			t.Errorf("%s is %q (send %q), want held back with the flag", e.URL, e.Status, e.Send)
		}
		held[urlPath(e.URL)] = true
	}
	for _, p := range declared {
		if !held[p] {
			t.Errorf("%s is not listed as held back: %v", p, held)
		}
	}
	reasons := 0
	for _, s := range rep.Skipped {
		if strings.Contains(s.Reason, "state change") && strings.Contains(s.Reason, "-send-state-changing") {
			reasons++
		}
	}
	if reasons != len(declared) {
		t.Errorf("the skipped list names %d held GETs, want %d: %+v", reasons, len(declared), rep.Skipped)
	}
	for _, n := range rep.Notes {
		if strings.Contains(n, "this run sent it") {
			t.Errorf("a note says a GET was sent that was not: %s", n)
		}
	}
	if rep.Error != "" || rep.Exit != 0 {
		t.Errorf("a held GET is a note, not a failure: exit %d %q", rep.Exit, rep.Error)
	}
}

// With -send-state-changing the same GETs are sent, and the summary calls
// sent exactly the ones the ledger holds a line for, as the app saw them.
func TestSendStateChangingSendsThemAndSaysSentOnlyForLedgerLines(t *testing.T) {
	app := newStateApp(t)
	lpath := filepath.Join(t.TempDir(), "run.ledger")
	rep, _ := runState(t, app, "-send-state-changing", "-ledger", lpath)
	if rep.StateChangingHeld != 0 {
		t.Errorf("nothing is held back with the flag: %d", rep.StateChangingHeld)
	}
	inLedger := map[string]bool{}
	for _, p := range ledgerGETs(t, lpath) {
		if statechange.OfPath(p) != "" || p == "/createdb" {
			inLedger[p] = true
		}
	}
	said := map[string]bool{}
	for _, e := range rep.StateChanging {
		if e.Status == stateSent {
			said[urlPath(e.URL)] = true
		}
	}
	for _, p := range declared {
		if !inLedger[p] || !said[p] || app.count("GET "+p) == 0 {
			t.Errorf("%s: ledger %v, summary %v, app saw %d", p, inLedger[p], said[p], app.count("GET "+p))
		}
	}
	if len(said) != len(inLedger) {
		t.Errorf("the summary calls %v sent, the ledger holds %v", said, inLedger)
	}

	// Without the flag the ledger has none of them, and the summary says none was sent.
	app2 := newStateApp(t)
	lpath2 := filepath.Join(t.TempDir(), "run2.ledger")
	rep2, _ := runState(t, app2, "-ledger", lpath2)
	lines := ledgerGETs(t, lpath2)
	for _, p := range lines {
		if slices.Contains(declared, p) {
			t.Errorf("the ledger holds a GET %s that was held back", p)
		}
	}
	// A held GET is no request: the wire, the ledger and the summary agree.
	if len(lines) != len(app2.asked()) || int(rep2.Requests) != len(lines) {
		t.Errorf("the app saw %d requests, the ledger holds %d, the summary says %d", len(app2.asked()), len(lines), rep2.Requests)
	}
	for _, e := range rep2.StateChanging {
		if e.Status == stateSent {
			t.Errorf("%s is said to be sent, and the ledger has no line for it", e.URL)
		}
	}
}

// A target the user gave is sent whatever its name says, and is named as given.
func TestGivenStateChangingTargetIsSent(t *testing.T) {
	app := newStateApp(t)
	egress.Reset()
	t.Cleanup(egress.Reset)
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", app.srv.URL + "/logout", "-sources", "none", "-depth", "0", "-no-paths", "-quiet", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if app.count("GET /logout") == 0 {
		t.Errorf("a target given by the user was held back: %v", app.asked())
	}
	if len(rep.StateChanging) != 1 || rep.StateChanging[0].Status != stateSent || rep.StateChangingHeld != 0 {
		t.Errorf("state_changing %+v held %d", rep.StateChanging, rep.StateChangingHeld)
	}
}

// The built-in -dirs list holds back its state-changing words (and their
// extensions) and says how many; a wordlist the user gives is asked in full.
func TestDirsBuiltinHoldsStateChangingWordsAndUserListDoesNot(t *testing.T) {
	app := newStateApp(t)
	egress.Reset()
	t.Cleanup(egress.Reset)
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"dirs", "-u", app.srv.URL, "-json", "-silent", "-db", filepath.Join(t.TempDir(), "d.db"), "-ledger", "off"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if n := app.count("GET /logout"); n != 0 {
		t.Errorf("the built-in list sent /logout %d times", n)
	}
	if !strings.Contains(errOut, "-send-state-changing") {
		t.Errorf("the summary does not say how to send the held words:\n%s", errOut)
	}
	words := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(words, []byte("logout\nreset\nusers\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app2 := newStateApp(t)
	egress.Reset()
	if _, errOut, err = captureBoth(t, func() error {
		return run([]string{"dirs", "-u", app2.srv.URL, "-w", words, "-json", "-silent", "-db", filepath.Join(t.TempDir(), "d2.db"), "-ledger", "off"})
	}); err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if app2.count("GET /logout") == 0 || app2.count("GET /reset") == 0 {
		t.Errorf("a wordlist of the user's was held back: %v", app2.asked())
	}
	app3 := newStateApp(t)
	egress.Reset()
	if _, errOut, err = captureBoth(t, func() error {
		return run([]string{"dirs", "-u", app3.srv.URL, "-send-state-changing", "-json", "-silent", "-db", filepath.Join(t.TempDir(), "d3.db"), "-ledger", "off"})
	}); err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if app3.count("GET /logout") == 0 {
		t.Errorf("-send-state-changing did not send the built-in list's /logout")
	}
}

// The estimate of a -dirs sweep with the built-in list is what the sweep
// sends: the held words are not in it, and with the flag they are.
func TestDirsEstimateCountsTheHeldWordsOut(t *testing.T) {
	for _, flags := range [][]string{nil, {"-send-state-changing"}} {
		app := newStateApp(t)
		egress.Reset()
		args := append([]string{"-url", app.srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-depth", "1", "-dirs", "@common"}, flags...)
		out, _, _ := cli(t, append([]string{"plan", "-json"}, args...)...)
		plan := planStageRequests(t, out, "fuzz")
		sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
		got := stageAmount(stagesOf(t, sum)["fuzz"], "actual", "requests")
		if plan != got {
			t.Errorf("flags %v: the plan estimates %v dirs requests, the run sent %v", flags, plan, got)
		}
	}
}

func planStageRequests(t *testing.T, out, stage string) float64 {
	t.Helper()
	sum := map[string]any{}
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatal(err)
	}
	est, _ := sum["estimate"].(map[string]any)
	for _, s := range est["stages"].([]any) {
		st := s.(map[string]any)
		if st["stage"] == stage {
			return stageAmount(st, "estimate", "requests")
		}
	}
	t.Fatalf("no %s stage: %s", stage, out)
	return 0
}

// urls -live does not ask an archived URL whose own path declares a state
// change unless -send-state-changing is given; it counts them as not asked.
func TestURLsLiveHoldsStateChangingArchivedURLs(t *testing.T) {
	app := newStateApp(t)
	rows := []urlcol.Row{{URL: app.srv.URL + "/logout.php"}, {URL: app.srv.URL + "/users/v1"}}
	for _, send := range []bool{false, true} {
		egress.Reset()
		var c common
		rep := newReport("urls")
		chk, err := verifyURLs(&c, rows, 50, 0, "", send, rep)
		if err != nil {
			t.Fatal(err)
		}
		saw := app.count("GET /logout.php")
		if !send && (saw != 0 || chk.held != 1) {
			t.Errorf("held back: the app saw /logout.php %d times, held %d", saw, chk.held)
		}
		if !send {
			chk.note(rep)
			if rep.Counts["not asked (state-changing)"] != 1 {
				t.Errorf("counts %v", rep.Counts)
			}
		}
		if send && (saw == 0 || chk.held != 0) {
			t.Errorf("with the flag: the app saw /logout.php %d times, held %d", saw, chk.held)
		}
	}
}

// The MCP server holds the flag as it holds the scope: a tool cannot ask
// for it, a server started with it passes it to the commands that find GETs.
func TestMCPHeldStateChangingFlag(t *testing.T) {
	for _, cmd := range []string{"run", "plan", "resume", "dirs", "params"} {
		if got := (heldRun{}).options(cmd); slices.Contains(got, "-send-state-changing") {
			t.Errorf("%s: the flag is passed without the server being started with it", cmd)
		}
		if got := (heldRun{SendStateChanging: true}).options(cmd); !slices.Contains(got, "-send-state-changing") {
			t.Errorf("%s: a server started with -send-state-changing does not pass it: %v", cmd, got)
		}
	}
	if !mcpRunFlags["send-state-changing"] {
		t.Errorf("a workspace started with the flag cannot be resumed by the tools")
	}
}

// A path list the user gives with -paths is asked in full, /logout included.
func TestUserPathListIsAsked(t *testing.T) {
	app := newStateApp(t)
	list := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(list, []byte("logout\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runState(t, app, "-paths", list, "-depth", "0")
	if app.count("GET /logout") == 0 {
		t.Errorf("a path of the user's own list was held back: %v", app.asked())
	}
}
