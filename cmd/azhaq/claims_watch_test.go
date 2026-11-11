package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
)

// changingSite is a site whose home page links the pages in links.
func changingSite(t *testing.T) (*httptest.Server, func(...string)) {
	t.Helper()
	var mu sync.Mutex
	links := []string{"/a"}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			var b strings.Builder
			for _, l := range links {
				fmt.Fprintf(&b, `<a href="%s">%s</a>`, l, l)
			}
			fmt.Fprintf(w, "<html><title>site</title>%s</html>", b.String())
			return
		}
		switch r.URL.Path {
		case "/a", "/b", "/c":
			fmt.Fprintf(w, "<html><title>%s</title></html>", r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(site.Close)
	return site, func(l ...string) { mu.Lock(); links = l; mu.Unlock() }
}

// runsOf is how many runs a workspace holds.
func runsOf(t *testing.T, db string) int {
	t.Helper()
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runs, err := st.Runs()
	if err != nil {
		t.Fatal(err)
	}
	return len(runs)
}

// The change set goes to every -notify URL, -notify-config provider and
// -notify-cmd when something changed, and with -always after every run; the
// baseline is printed and not sent, unless -always; without -every watch
// runs once.
func TestWatchSendsToEveryTargetWhenSomethingChangedOrAlways(t *testing.T) {
	site, setLinks := changingSite(t)
	var hooks [3]atomic.Int32
	servers := make([]*httptest.Server, 3)
	for i := range servers {
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hooks[i].Add(1)
		}))
		defer servers[i].Close()
	}
	cmdFile := filepath.Join(t.TempDir(), "cmd.out")
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: ops\n    custom_webhook_url: "+servers[2].URL+"/ops\n    custom_method: POST\n")
	db := filepath.Join(t.TempDir(), "ws.db")
	got := func() [4]int {
		raw, _ := os.ReadFile(cmdFile)
		return [4]int{int(hooks[0].Load()), int(hooks[1].Load()), int(hooks[2].Load()), strings.Count(string(raw), "\n")}
	}
	watch := func(extra ...string) string {
		out := capture(t, func() error {
			return cmdWatch(append([]string{"-db", db, "-notify", servers[0].URL + "/a", "-notify", servers[1].URL + "/b", "-notify-config", pc, "-notify-rate", "0",
				"-notify-cmd", "cat > /dev/null; echo x >> " + cmdFile}, append(extra, "--", "-url", site.URL+"/", "-allow", "127.0.0.1", "-no-paths")...))
		})
		return out
	}
	base := watch()
	if !strings.Contains(base, "first run") || got() != [4]int{} || runsOf(t, db) != 1 {
		t.Fatalf("the baseline is printed and not sent, %d run: %v\n%s", runsOf(t, db), got(), base)
	}
	setLinks("/a", "/b")
	if out := watch(); !strings.Contains(out, "+ 1 URLs") || got() != [4]int{1, 1, 1, 1} || runsOf(t, db) != 2 {
		t.Fatalf("a change goes to every target, in one run: %v, %d runs\n%s", got(), runsOf(t, db), out)
	}
	if out := watch(); !strings.Contains(out, "no change") || got() != [4]int{1, 1, 1, 1} {
		t.Fatalf("an unchanged run sends nothing: %v\n%s", got(), out)
	}
	watch("-always")
	if got() != [4]int{2, 2, 2, 2} {
		t.Errorf("-always sends after every run: %v", got())
	}
}

// -always sends the baseline, and every run after it.
func TestWatchAlwaysSendsTheBaselineAndEveryRunAfterIt(t *testing.T) {
	site, _ := changingSite(t)
	var n atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	defer hook.Close()
	db := filepath.Join(t.TempDir(), "ws.db")
	for i := 1; i <= 3; i++ {
		capture(t, func() error {
			return cmdWatch([]string{"-db", db, "-always", "-notify", hook.URL, "-notify-rate", "0", "--", "-url", site.URL + "/", "-allow", "127.0.0.1", "-no-paths"})
		})
		if int(n.Load()) != i {
			t.Errorf("after run %d the hook got %d messages", i, n.Load())
		}
	}
}

// The text names each kind of change with at most 20 lines each and counts
// the rest, and says "no change" when nothing changed.
func TestWatchTextHasAtMost20LinesOfAKindAndSaysNoChange(t *testing.T) {
	var urls, gone []string
	for i := 0; i < 25; i++ {
		urls = append(urls, fmt.Sprintf("http://h/new%02d", i))
	}
	for i := 0; i < 3; i++ {
		gone = append(gone, fmt.Sprintf("http://h/old%d", i))
	}
	c := changes{DB: "w.db", Run: time.Now(), Previous: time.Now(), URLs: urls, GoneURLs: gone, Hosts: []string{"a.test (1.1.1.1)"}}
	text := c.text()
	for _, want := range []string{"+ 1 hostnames that resolve\n", "+ 25 URLs\n", "    … and 5 more\n", "- 3 URLs gone\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if n := strings.Count(text, "http://h/new"); n != 20 {
		t.Errorf("%d lines of new URLs, want 20", n)
	}
	for _, kind := range []string{"web services", "API routes", "hosts whose open ports changed", "pages that answer differently", "hostnames gone", "URLs"} {
		if kind != "URLs" && strings.Contains(text, kind) {
			t.Errorf("a kind of change that did not happen is named: %s", kind)
		}
	}
	if no := (changes{DB: "w.db", Run: time.Now(), Previous: time.Now()}).text(); !strings.Contains(no, "no change\n") {
		t.Errorf("%q", no)
	}
}

// -every runs again after that long, until a signal stops it, which exits 0
// when it lands between two cycles;
// a run that ended 3 or 4 does not end the loop; a notification that did not
// arrive stays on stderr.
func TestWatchEveryRunsAgainUntilASignalAndOnlyASignalEndsIt(t *testing.T) {
	site, _ := changingSite(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer bad.Close()
	dead := bad.URL + "/hook/secret-token" // a 400 is tried once, and does not arrive
	for _, c := range []struct {
		name string
		run  []string
		note string // what a run says it ended with
	}{
		{"complete runs", []string{"-url", site.URL + "/", "-allow", "127.0.0.1", "-no-paths"}, ""},
		{"runs stopped by a limit (exit 4)", []string{"-url", site.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-max-requests", "1"}, "stopped"},
		{"runs that failed (exit 3)", []string{"-url", "http://" + deadAddr(t) + "/", "-allow", "127.0.0.1", "-no-paths"}, "failed"},
	} {
		db := filepath.Join(t.TempDir(), "ws.db")
		file := filepath.Join(t.TempDir(), "n")
		// The third cycle signals watch from outside, as ^C does, while it waits
		// for the next one: nothing is cut, so the exit is 0.
		cmd := "echo x >> " + file + "; P=$PPID; [ $(wc -l < " + file + ") -ge 3 ] && { (sleep 0.4; kill -TERM $P) >/dev/null 2>&1 & }; true"
		var errOut string
		var err error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, errOut, err = captureAll(t, func() error {
				return cmdWatch(append([]string{"-db", db, "-every", "1s", "-always", "-notify", dead, "-notify-rate", "0", "-notify-cmd", cmd, "--"}, c.run...))
			})
		}()
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
			<-done
			t.Fatalf("%s: watch did not stop", c.name)
		}
		if err != nil {
			t.Errorf("%s: a signal ends watch with %v, want exit 0", c.name, err)
		}
		if n := runsOf(t, db); n < 3 {
			t.Errorf("%s: %d runs, a run that ended 3 or 4 does not end the loop", c.name, n)
		}
		if got := strings.Count(errOut, "azhaq watch: POST "+strings.TrimSuffix(dead, "/hook/secret-token")+"/…:"); got < 3 || strings.Contains(errOut, "secret-token") {
			t.Errorf("%s: %d lines on stderr for the notification that did not arrive:\n%s", c.name, got, errOut)
		}
	}
}

// Without -every watch runs once and exits with the code of its run: 0, 4
// when a limit stopped it, 3 when it failed; a notification that did not
// arrive is exit 3, and the run's own 3 or 4 wins.
func TestWatchWithoutEveryExitsWithTheCodeOfItsRun(t *testing.T) {
	site, _ := changingSite(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer bad.Close()
	run := func(extra []string, run ...string) (int, string) {
		db := filepath.Join(t.TempDir(), "ws.db")
		_, errOut, err := captureAll(t, func() error {
			return cmdWatch(append(append([]string{"-db", db, "-notify-rate", "0"}, extra...), append([]string{"--"}, run...)...))
		})
		if n := runsOf(t, db); n != 1 {
			t.Errorf("%d runs without -every", n)
		}
		return exitCode(err), errOut
	}
	ok := []string{"-url", site.URL + "/", "-allow", "127.0.0.1", "-no-paths"}
	limit := append(append([]string{}, ok...), "-max-requests", "1")
	failed := []string{"-url", "http://" + deadAddr(t) + "/", "-allow", "127.0.0.1", "-no-paths"}
	for _, c := range []struct {
		name  string
		extra []string
		args  []string
		want  int
	}{
		{"a complete run", nil, ok, exitOK},
		{"a run stopped by a limit", nil, limit, exitLimit},
		{"a run that failed", nil, failed, exitPartial},
		{"a notification that did not arrive", []string{"-always", "-notify", bad.URL + "/hook"}, ok, exitPartial},
		{"a limit and a notification that did not arrive", []string{"-always", "-notify", bad.URL + "/hook"}, limit, exitLimit},
	} {
		if got, errOut := run(c.extra, c.args...); got != c.want {
			t.Errorf("%s: exit %d, want %d\n%s", c.name, got, c.want, errOut)
		}
	}
}

// Without -db, or with no run options after --, watch exits 2 and says how to
// call it; a run that cannot start ends watch with its error, even with -every.
func TestWatchUsageAndARunThatCannotStart(t *testing.T) {
	for _, args := range [][]string{
		{"--", "-url", "http://127.0.0.1:9/"},
		{"-db", filepath.Join(t.TempDir(), "w.db")},
		{"-db", filepath.Join(t.TempDir(), "w.db"), "--"},
	} {
		err := cmdWatch(args)
		if exitCode(err) != exitUsage || err == nil || !strings.Contains(err.Error(), "usage: azhaq watch -db WORKSPACE.db") {
			t.Errorf("%q: %v", args, err)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := captureAll(t, func() error {
			return cmdWatch([]string{"-db", filepath.Join(t.TempDir(), "w.db"), "-every", "1h", "--", "-url", "http://127.0.0.1:9/", "-no-such-flag"})
		})
		done <- err
	}()
	select {
	case err := <-done:
		if exitCode(err) != exitUsage {
			t.Errorf("a run that cannot start: %v", err)
		}
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		t.Fatal("a run that cannot start did not end watch")
	}
}

// Every delivery goes through notify's sender: a webhook and a provider are
// tried three times on a 5xx, a 4xx once, and each try is a line of the ledger
// that names the host alone; with -ledger off nothing is kept and the
// requests are still counted.
func TestWatchDeliveriesGoThroughOneSenderAndAreCounted(t *testing.T) {
	site, _ := changingSite(t)
	for _, c := range []struct {
		status, tries int
	}{{500, 3}, {404, 1}, {0, 3}} { // 0: the connection is dropped
		var hookN, provN atomic.Int32
		answer := func(n *atomic.Int32) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				n.Add(1)
				if c.status == 0 {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				w.WriteHeader(c.status)
			}
		}
		hook := httptest.NewServer(answer(&hookN))
		prov := httptest.NewServer(answer(&provN))
		pc := writeTemp(t, "pc.yaml", "custom:\n  - id: ops\n    custom_webhook_url: "+prov.URL+"/ops/secret\n    custom_method: POST\n")
		variants := []bool{false}
		if c.tries == 1 {
			variants = append(variants, true) // -ledger off once: the retries are slow
		}
		for _, ledgerOff := range variants {
			hookN.Store(0)
			provN.Store(0)
			db := filepath.Join(t.TempDir(), "ws.db")
			run := []string{"-url", site.URL + "/", "-allow", "127.0.0.1", "-no-paths"}
			if ledgerOff {
				run = append(run, "-ledger", "off")
			}
			_, errOut, err := captureAll(t, func() error {
				return cmdWatch(append([]string{"-db", db, "-json", "-always", "-notify", hook.URL + "/hook/secret", "-notify-config", pc, "-notify-rate", "0", "--"}, run...))
			})
			if exitCode(err) != exitPartial {
				t.Errorf("status %d: exit %d", c.status, exitCode(err))
			}
			if int(hookN.Load()) != c.tries || int(provN.Load()) != c.tries {
				t.Errorf("status %d: the webhook was tried %d times and the provider %d, want %d each", c.status, hookN.Load(), provN.Load(), c.tries)
			}
			var rep report
			for _, l := range strings.Split(errOut, "\n") {
				var r report
				if strings.HasPrefix(l, "{") && json.Unmarshal([]byte(l), &r) == nil && r.Command == "watch" {
					rep = r
				}
			}
			if rep.Results != 2*c.tries {
				t.Errorf("status %d, ledger off %v: the summary counts %d requests, the receivers got %d", c.status, ledgerOff, rep.Results, 2*c.tries)
			}
			_, statErr := os.Stat(db + ".ledger.jsonl")
			if ledgerOff != (statErr != nil) {
				t.Errorf("status %d, ledger off %v: the ledger file: %v", c.status, ledgerOff, statErr)
			}
		}
		hook.Close()
		prov.Close()
	}
}
