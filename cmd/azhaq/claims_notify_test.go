package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// hookServer answers by path: /ok 200; /flaky a 429 first, then 200; /bad 400;
// /down 500; /echo 400 with the body in echo. The refusals ask to be tried
// again in 10 ms, so a test need not wait seconds.
func hookServer(t *testing.T, echo string) (*httptest.Server, func(path string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		hits[r.URL.Path]++
		n := hits[r.URL.Path]
		mu.Unlock()
		switch {
		case r.URL.Path == "/flaky" && n == 1:
			w.Header().Set("Retry-After", "0.01")
			w.WriteHeader(429)
		case r.URL.Path == "/bad":
			w.WriteHeader(400)
		case r.URL.Path == "/down":
			w.Header().Set("Retry-After", "0.01")
			w.WriteHeader(500)
		case strings.HasPrefix(r.URL.Path, "/echo"):
			w.WriteHeader(400)
			io.WriteString(w, echo)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func(p string) int { mu.Lock(); defer mu.Unlock(); return hits[p] }
}

func customEntries(srv *httptest.Server, paths ...string) string {
	var b strings.Builder
	b.WriteString("custom:\n")
	for _, p := range paths {
		b.WriteString("  - id: " + strings.Trim(p, "/") + "\n    custom_webhook_url: " + srv.URL + p + "\n    custom_method: POST\n")
	}
	return b.String()
}

// The summary names every entry a message did not reach, with its id and the
// reason; counts has delivered, requests sent (every try) and, only when a
// message needed more tries, retried.
func TestNotifySummaryNamesEveryEntryAndCountsTheTries(t *testing.T) {
	srv, _ := hookServer(t, "")
	pc := writeTemp(t, "pc.yaml", customEntries(srv, "/ok", "/flaky", "/bad", "/down"))
	in := writeTemp(t, "in.txt", "one\n")
	_, errOut, err := captureAll(t, func() error { return cmdNotify([]string{"-pc", pc, "-i", in, "-rl", "0", "-json"}) })
	if exitCode(err) != exitPartial {
		t.Fatalf("exit %d, want 3", exitCode(err))
	}
	var sum report
	if err := json.Unmarshal([]byte(strings.TrimSpace(errOut)), &sum); err != nil {
		t.Fatalf("%q: %v", errOut, err)
	}
	if sum.Counts["delivered"] != 2 || sum.Counts["retried"] != 1 || sum.Counts["requests sent"] != 1+2+1+3 {
		t.Errorf("counts %v, want delivered 2, retried 1, requests sent 7", sum.Counts)
	}
	got := map[string]string{}
	for _, f := range sum.Failed {
		for _, tg := range f.Targets {
			got[tg] = f.Collector + ": " + f.Error
		}
	}
	if len(got) != 2 || !strings.Contains(got["id bad"], "400") || !strings.Contains(got["id down"], "500") || !strings.Contains(got["id down"], "after 3 tries") {
		t.Errorf("failed entries %v: want id bad (a 400) and id down (a 500 after 3 tries), and no other", got)
	}
	// The text summary says the same, by id.
	srv2, _ := hookServer(t, "")
	pc2 := writeTemp(t, "pc2.yaml", customEntries(srv2, "/ok", "/bad", "/down"))
	_, errOut, err = captureAll(t, func() error { return cmdNotify([]string{"-pc", pc2, "-i", in, "-rl", "0"}) })
	if exitCode(err) != exitPartial || !strings.Contains(errOut, "custom failed:") || !strings.Contains(errOut, "id bad") || !strings.Contains(errOut, "id down") || strings.Contains(errOut, "id ok") {
		t.Errorf("exit %d, summary %q", exitCode(err), errOut)
	}
	// Every first try answered: no retried, requests sent is the deliveries.
	srv3, _ := hookServer(t, "")
	pc3 := writeTemp(t, "pc3.yaml", customEntries(srv3, "/ok"))
	_, errOut, err = captureAll(t, func() error { return cmdNotify([]string{"-pc", pc3, "-i", in, "-rl", "0", "-json"}) })
	var clean report
	json.Unmarshal([]byte(strings.TrimSpace(errOut)), &clean)
	if err != nil || clean.Counts["delivered"] != 1 || clean.Counts["requests sent"] != 1 {
		t.Errorf("exit %d, counts %v", exitCode(err), clean.Counts)
	}
	if _, ok := clean.Counts["retried"]; ok {
		t.Errorf("retried is in the counts of a run with no retry: %v", clean.Counts)
	}
}

// Exit 2 and nothing sent when there is no provider config, the config has a
// key the schema does not have, -p names no provider or a -p or -id filter
// matches nothing.
func TestNotifyUsageErrorsSendNothing(t *testing.T) {
	srv, _ := hookServer(t, "")
	var posts int
	var mu sync.Mutex
	count := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); posts++; mu.Unlock() }))
	t.Cleanup(count.Close)
	_ = srv
	good := customEntries(count, "/a")
	in := writeTemp(t, "in.txt", "x\n")
	t.Setenv("HOME", t.TempDir()) // no default config
	for name, args := range map[string][]string{
		"no provider config":   {"-i", in},
		"a missing config":     {"-pc", filepath.Join(t.TempDir(), "none.yaml"), "-i", in},
		"a mistyped key":       {"-pc", writeTemp(t, "typo.yaml", good+"slack:\n  - slack_webhok_url: https://hooks.slack.com/services/T/B/X\n"), "-i", in},
		"-p names no provider": {"-pc", writeTemp(t, "ok1.yaml", good), "-i", in, "-p", "sms"},
		"-p matches nothing":   {"-pc", writeTemp(t, "ok2.yaml", good), "-i", in, "-p", "slack"},
		"-id matches nothing":  {"-pc", writeTemp(t, "ok3.yaml", good), "-i", in, "-id", "zzz"},
	} {
		if _, _, err := captureAll(t, func() error { return cmdNotify(args) }); exitCode(err) != exitUsage {
			t.Errorf("%s: exit %d (%v), want 2", name, exitCode(err), err)
		}
	}
	// watch -notify-config without a config stops the same way.
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<title>t</title>")) }))
	defer site.Close()
	_, _, err := captureAll(t, func() error {
		return cmdWatch([]string{"-db", filepath.Join(t.TempDir(), "w.db"), "-always", "-notify-config", filepath.Join(t.TempDir(), "none.yaml"), "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
	})
	if exitCode(err) != exitUsage {
		t.Errorf("watch -notify-config with no file: exit %d, want 2", exitCode(err))
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 0 {
		t.Errorf("%d notifications were sent by runs that were refused", posts)
	}
}

// -no-color and -disable-update-check do nothing: the same messages go out,
// and nothing but the hook is asked (azhaq checks for no updates).
func TestNotifyIgnoresNoColorAndUpdateCheckAndAsksNothingElse(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: c\n    custom_webhook_url: "+srv.URL+"/in\n    custom_method: POST\n")
	in := writeTemp(t, "in.txt", "aaa\nbbb\n")
	led := filepath.Join(t.TempDir(), "n.ledger.jsonl")
	run := func(extra ...string) (string, []string) {
		rec.mu.Lock()
		rec.bodies = nil
		rec.mu.Unlock()
		os.Remove(led)
		out, errOut, err := captureAll(t, func() error {
			return cmdNotify(append([]string{"-pc", pc, "-i", in, "-rl", "0", "-ledger", led}, extra...))
		})
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return out, append([]string(nil), rec.bodies...)
	}
	out1, bodies1 := run()
	for _, extra := range [][]string{{"-no-color"}, {"-nc"}, {"-disable-update-check"}, {"-duc"}, {"-nc", "-duc"}} {
		out2, bodies2 := run(extra...)
		if out1 != out2 || strings.Join(bodies1, "|") != strings.Join(bodies2, "|") {
			t.Errorf("%v changed what was sent: %q %q against %q %q", extra, out2, bodies2, out1, bodies1)
		}
		var targets []string
		if err := ledger.Read(led, func(e ledger.Entry) error {
			if e.Kind == "http" {
				targets = append(targets, e.Target)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(targets) != 2 || targets[0] != srv.URL+"/…" || targets[1] != srv.URL+"/…" {
			t.Errorf("%v: the ledger lists requests to %v: want the 2 to the hook and none to anything else", extra, targets)
		}
	}
}

// -rl is the most requests a second for every provider together; its default is 1.
func TestNotifyRateLimitIsSharedByProviders(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	port := strings.Split(srv.URL, ":")[2]
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: c\n    custom_webhook_url: "+srv.URL+"/c\n    custom_method: POST\ngotify:\n  - id: g\n    gotify_host: 127.0.0.1\n    gotify_port: \""+port+"\"\n    gotify_token: gtfyaMODERNTOKEN\n    gotify_disabletls: true\n")
	in := writeTemp(t, "in.txt", "a\nb\nc\n")
	took := func(rl string) time.Duration {
		start := time.Now()
		if _, errOut, err := captureAll(t, func() error { return cmdNotify([]string{"-pc", pc, "-i", in, "-rl", rl, "-silent"}) }); err != nil {
			t.Fatalf("%v %s", err, errOut)
		}
		return time.Since(start)
	}
	free := took("0")
	paced := took("10") // 6 requests to 2 providers: 5 waits of 100 ms
	if paced < 450*time.Millisecond || paced < free+300*time.Millisecond {
		t.Errorf("-rl 10 took %v and -rl 0 %v: the 6 requests of 2 providers were not paced together", paced, free)
	}
	rec.mu.Lock()
	n := len(rec.bodies)
	rec.mu.Unlock()
	if n != 12 {
		t.Errorf("%d requests, want 6 for each of the two runs", n)
	}
	fs := newFlags("notify")
	var o notifyOpts
	o.register(fs)
	if fs.Lookup("rl").DefValue != "1" || fs.Lookup("rate-limit").DefValue != "1" {
		t.Errorf("the default of -rl is %s", fs.Lookup("rl").DefValue)
	}
}

// watch's notifications follow the same delivery rules as notify's: a 4xx is
// not tried again, a 429 is tried three times, and a message lost is exit 3.
func TestWatchNotificationsFollowTheDeliveryRules(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<title>t</title>")) }))
	defer site.Close()
	srv, hits := hookServer(t, "")
	for path, want := range map[string]int{"/bad": 1, "/down": 3, "/ok": 1} {
		_, _, err := captureAll(t, func() error {
			return cmdWatch([]string{"-db", filepath.Join(t.TempDir(), "w.db"), "-always", "-notify", srv.URL + path, "-notify-rate", "0", "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
		})
		if got := hits(path); got != want || (path == "/ok") != (err == nil) || (path != "/ok" && exitCode(err) != exitPartial) {
			t.Errorf("%s: %d requests (want %d), exit %d", path, got, want, exitCode(err))
		}
	}
	// With the workspace's ledger: one line for each try, by the host.
	db := filepath.Join(t.TempDir(), "w.db")
	_, _, err := captureAll(t, func() error {
		return cmdWatch([]string{"-db", db, "-always", "-notify", srv.URL + "/ok", "-notify-rate", "0", "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
	})
	if err != nil {
		t.Fatal(err)
	}
	hooks := 0
	ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
		if e.Class == ledger.ClassSource && e.Method == "POST" && e.Target == srv.URL+"/…" {
			hooks++
		}
		return nil
	})
	if hooks != 1 {
		t.Errorf("the workspace's ledger lists %d notifications, want 1", hooks)
	}
}

// A webhook URL is never printed: not on stdout or stderr, with -v or -json,
// when it works or fails, nor in the ledger, which lists its host; no error
// holds a secret of the config even if the server repeats it.
func TestNotifyPrintsNoWebhookAndNoSecret(t *testing.T) {
	const tok, hdr = "TOKEN-zq81x7mpl", "k9d8s7a6x5"
	srv, _ := hookServer(t, hdr) // /echo answers 400 with the header value
	cfg := "custom:\n" +
		"  - id: good\n    custom_webhook_url: " + srv.URL + "/ok/" + tok + "?key=" + tok + "\n    custom_method: POST\n" +
		"  - id: echoing\n    custom_webhook_url: " + srv.URL + "/echo/" + tok + "?key=" + tok + "\n    custom_method: POST\n    custom_headers:\n      X-Key: " + hdr + "\n"
	pc := writeTemp(t, "pc.yaml", cfg)
	in := writeTemp(t, "in.txt", "one\n")
	led := filepath.Join(t.TempDir(), "n.ledger.jsonl")
	for _, extra := range [][]string{{"-v"}, {"-json"}, {"-v", "-json"}, {}} {
		os.Remove(led)
		out, errOut, err := captureAll(t, func() error {
			return cmdNotify(append([]string{"-pc", pc, "-i", in, "-rl", "0", "-ledger", led}, extra...))
		})
		if exitCode(err) != exitPartial {
			t.Fatalf("%v: exit %d", extra, exitCode(err))
		}
		raw, _ := os.ReadFile(led)
		for name, s := range map[string]string{"stdout": out, "stderr": errOut, "ledger": string(raw)} {
			if strings.Contains(s, tok) || strings.Contains(s, "zq81x7mpl") || strings.Contains(s, "/ok/") || strings.Contains(s, "?key=") || strings.Contains(s, hdr) {
				t.Errorf("%v: the webhook or a secret is in the %s:\n%s", extra, name, s)
			}
		}
		if !strings.Contains(string(raw), fmt.Sprintf(`"target":"%s/…"`, srv.URL)) {
			t.Errorf("%v: the ledger does not list the host: %s ", extra, raw)
		}
	}
}

// Without -ledger nothing is kept: notify has no workspace to keep a ledger beside.
func TestNotifyWithoutLedgerKeepsNothing(t *testing.T) {
	srv, _ := hookServer(t, "")
	pc := writeTemp(t, "pc.yaml", customEntries(srv, "/ok"))
	in := writeTemp(t, "in.txt", "one\n")
	work, home := t.TempDir(), t.TempDir()
	t.Chdir(work)
	t.Setenv("HOME", home)
	t.Setenv("AZHAQ_DATA_DIR", home)
	if _, errOut, err := captureAll(t, func() error { return cmdNotify([]string{"-pc", pc, "-i", in, "-rl", "0"}) }); err != nil {
		t.Fatalf("%v %s", err, errOut)
	}
	for _, d := range []string{work, home} {
		if files, _ := filepath.Glob(filepath.Join(d, "*")); len(files) != 0 {
			t.Errorf("notify left %v in %s", files, d)
		}
	}
}

// Text from a pipe is sent, a line a message.
func TestNotifyReadsTextFromAPipe(t *testing.T) {
	rec := &recorder{}
	srv := rec.server(200)
	defer srv.Close()
	pc := writeTemp(t, "pc.yaml", "custom:\n  - id: c\n    custom_webhook_url: "+srv.URL+"/in\n    custom_method: POST\n")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	was := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = was })
	go func() { io.WriteString(w, "first\nsecond\n"); w.Close() }()
	if _, errOut, err := captureAll(t, func() error { return cmdNotify([]string{"-pc", pc, "-rl", "0"}) }); err != nil {
		t.Fatalf("%v %s", err, errOut)
	}
	if strings.Join(rec.bodies, "|") != "first|second" {
		t.Errorf("posted %q", rec.bodies)
	}
}
