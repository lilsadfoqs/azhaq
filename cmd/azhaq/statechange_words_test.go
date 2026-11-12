package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// wordsApp links the GETs a control page, an installer and a job runner
// have, and names read-only pages with the same letters in them. It counts
// the requests by path and query.
type wordsApp struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []string
}

// held are the requests the app's pages name, with the word that holds each.
var wordsHeld = map[string]string{
	"/start_over":                      "start_over",
	"/install/ajax.php":                "install",
	"/api/ScriptCron/run":              "run",
	"/admin/restart":                   "restart",
	"/api/jobs/execute":                "execute",
	"/server/index.php?s=/user/logout": "logout",
}

// wordsSent are read-only pages that hold a word of the list as a part of a
// longer one.
var wordsSent = []string{"/startup-guide", "/running-jobs", "/uploads", "/about", "/installed-plugins"}

func newWordsApp(t *testing.T) *wordsApp {
	t.Helper()
	a := &wordsApp{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.got = append(a.got, r.URL.RequestURI())
		a.mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>app</title><a href="/start_over">s</a> <a href="/install/ajax.php">i</a> <a href="/startup-guide">g</a> `+
				`<a href="/running-jobs">j</a> <a href="/uploads">u</a> <a href="/about">a</a> <a href="/installed-plugins">p</a> `+
				`<script src="/app.js"></script>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/ScriptCron/run"); fetch("/admin/restart"); fetch("/api/jobs/execute"); fetch("/server/index.php?s=/user/logout");`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>ok")
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *wordsApp) count(uri string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, g := range a.got {
		if g == uri {
			n++
		}
	}
	return n
}

func runWords(t *testing.T, a *wordsApp, db string, flags ...string) report {
	t.Helper()
	egress.Reset()
	t.Cleanup(egress.Reset)
	args := append([]string{"run", "-url", a.srv.URL + "/", "-sources", "none", "-quiet", "-json", "-no-paths", "-no-favicon", "-depth", "3", "-db", db, "-ledger", "off"}, flags...)
	_, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	return lastReport(t, errOut)
}

// queryKeys are the keys of the rows query -json gives for the workspace.
func queryKeys(t *testing.T, args ...string) []string {
	t.Helper()
	out, _, err := captureBoth(t, func() error { return run(append([]string{"query", "-json"}, args...)) })
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, l := range lines(out) {
		var row struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		keys = append(keys, row.Key)
	}
	return keys
}

// A link, a script's calls and a query value that is a path name GETs that
// run, restart, install or end a session: none is sent, each is in the
// summary with its word and the flag that sends it, and each is a skipped row
// of the workspace that query finds. The pages whose names only hold those
// letters are sent.
func TestRunHoldsTheGETsNamedRunRestartInstall(t *testing.T) {
	app := newWordsApp(t)
	db := filepath.Join(t.TempDir(), "w.db")
	rep := runWords(t, app, db)
	for uri := range wordsHeld {
		if n := app.count(uri); n != 0 {
			t.Errorf("%s was sent %d times", uri, n)
		}
	}
	for _, uri := range wordsSent {
		if app.count(uri) == 0 {
			t.Errorf("%s names no word of the list and was not sent: %v", uri, app.got)
		}
	}
	for uri, word := range wordsHeld {
		found := false
		for _, e := range rep.StateChanging {
			if strings.HasSuffix(e.URL, uri) {
				found = true
				if e.Word != word || e.Status != stateHeld || e.Send != neterr.SendFlag {
					t.Errorf("%s: word %q status %q send %q, want %q, held back and %s", uri, e.Word, e.Status, e.Send, word, neterr.SendFlag)
				}
			}
		}
		if !found {
			t.Errorf("%s is not in state_changing: %+v", uri, rep.StateChanging)
		}
		listed := false
		for _, s := range rep.Skipped {
			listed = listed || strings.HasSuffix(s.Target, uri) && strings.Contains(s.Reason, neterr.SendFlag) && strings.Contains(s.Reason, `"`+word+`"`)
		}
		if !listed {
			t.Errorf("%s is not listed under skipped with its word and the flag: %+v", uri, rep.Skipped)
		}
	}
	if rep.StateChangingHeld != len(wordsHeld) {
		t.Errorf("state_changing_held %d, want %d", rep.StateChangingHeld, len(wordsHeld))
	}
	// The workspace keeps each held GET as a skipped row of its own.
	keys := queryKeys(t, "-db", db, "-coverage", "skipped", "-type", "URL")
	for uri := range wordsHeld {
		if !slices.ContainsFunc(keys, func(k string) bool { return strings.HasSuffix(k, uri) }) {
			t.Errorf("query -coverage skipped does not find %s: %v", uri, keys)
		}
	}
	for _, uri := range wordsSent {
		if slices.ContainsFunc(keys, func(k string) bool { return strings.HasSuffix(k, uri) }) {
			t.Errorf("query lists %s as skipped, and it was sent", uri)
		}
	}
	if got := queryKeys(t, "-db", db, "-match", "install"); !slices.ContainsFunc(got, func(k string) bool { return strings.HasSuffix(k, "/install/ajax.php") }) {
		t.Errorf("query -match install does not find the held GET: %v", got)
	}

	// -send-state-changing sends them all.
	app2 := newWordsApp(t)
	rep2 := runWords(t, app2, filepath.Join(t.TempDir(), "w2.db"), "-send-state-changing")
	for uri := range wordsHeld {
		if app2.count(uri) != 1 {
			t.Errorf("-send-state-changing: %s was sent %d times", uri, app2.count(uri))
		}
	}
	if rep2.StateChangingHeld != 0 {
		t.Errorf("with the flag %d are held", rep2.StateChangingHeld)
	}
}

// dirs holds the words that name a state change as run does, keeps each as a
// skipped row of its own URL, and leaves the base URL it asked them under
// alone.
func TestDirsKeepsEachHeldWordAsASkippedRow(t *testing.T) {
	app := newWordsApp(t)
	db := filepath.Join(t.TempDir(), "d.db")
	egress.Reset()
	t.Cleanup(egress.Reset)
	words := wlist(t, "start_over", "install", "admin", "uploads", "running-jobs", "purge-all", "wipe")
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", app.srv.URL + "/", "-w", words, "-ac=false", "-db", db, "-ledger", "off", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	heldWords := map[string]string{"/start_over": "start_over", "/install": "install", "/purge-all": "purge", "/wipe": "wipe"}
	for p, word := range heldWords {
		if app.count(p) != 0 {
			t.Errorf("%s was sent", p)
		}
		found := false
		for _, e := range rep.StateChanging {
			found = found || strings.HasSuffix(e.URL, p) && e.Word == word && e.Send == neterr.SendFlag
		}
		if !found {
			t.Errorf("%s (%s) is not in state_changing: %+v", p, word, rep.StateChanging)
		}
	}
	for _, p := range []string{"/admin", "/uploads", "/running-jobs"} {
		if app.count(p) != 1 {
			t.Errorf("%s was sent %d times", p, app.count(p))
		}
	}
	keys := queryKeys(t, "-db", db, "-coverage", "skipped", "-type", "URL")
	for p := range heldWords {
		if !slices.ContainsFunc(keys, func(k string) bool { return strings.HasSuffix(k, p) }) {
			t.Errorf("query -coverage skipped does not find %s: %v", p, keys)
		}
	}
	for _, k := range keys {
		if strings.TrimSuffix(k, "/") == app.srv.URL {
			t.Errorf("the base URL %s is stored as skipped: %v", k, keys)
		}
	}
	if got := queryKeys(t, "-db", db, "-match", "purge"); len(got) == 0 {
		t.Error("query -match purge finds nothing")
	}
}

// fuzz stores each input it held back as a skipped row of its own URL.
func TestFuzzKeepsEachHeldInputAsASkippedRow(t *testing.T) {
	app := newWordsApp(t)
	db := filepath.Join(t.TempDir(), "f.db")
	egress.Reset()
	t.Cleanup(egress.Reset)
	_, errOut, err := captureBoth(t, func() error {
		return cmdFuzz([]string{"-u", app.srv.URL + "/FUZZ", "-w", wlist(t, "start_over", "restart", "admin", "about"), "-ac=false", "-quiet", "-db", db, "-ledger", "off", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	for _, p := range []string{"/start_over", "/restart"} {
		if app.count(p) != 0 {
			t.Errorf("%s was sent", p)
		}
	}
	keys := queryKeys(t, "-db", db, "-coverage", "skipped", "-type", "URL")
	for _, p := range []string{"/start_over", "/restart"} {
		if !slices.ContainsFunc(keys, func(k string) bool { return strings.HasSuffix(k, p) }) {
			t.Errorf("query -coverage skipped does not find %s: %v", p, keys)
		}
	}
	if slices.ContainsFunc(keys, func(k string) bool { return strings.HasSuffix(k, "/about") || strings.HasSuffix(k, "/admin") }) {
		t.Errorf("a word that was sent is stored as skipped: %v", keys)
	}
}
