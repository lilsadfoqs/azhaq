package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// noSandboxChrome is a Chrome that exits the way one does where the system
// gives it no sandbox, unless it is started with --no-sandbox.
func noSandboxChrome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the stand-in is a shell script")
	}
	real, err := browser.Find()
	if err != nil {
		t.Skip(err)
	}
	script := filepath.Join(t.TempDir(), "chrome")
	body := fmt.Sprintf(`#!/bin/sh
for a in "$@"; do
  if [ "$a" = "--no-sandbox" ]; then exec %q "$@"; fi
done
echo "[1:1:0101/000000.000000:FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! Update your kernel" >&2
exit 1
`, real)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

// Every command that starts Chrome refuses to, where the system gives it no
// sandbox, unless -chrome-no-sandbox is given: with exit 2, a message that
// names the flag, and before any request to the target.
func TestChromeIsNotRunWithoutItsSandboxUnlessAllowed(t *testing.T) {
	t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
	t.Setenv("AZHAQ_CHROME", noSandboxChrome(t))
	var asked atomic.Int64
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>home</title><form action="/login" method=post><input name=u><input type=password name=p></form></html>`)
	}))
	defer site.Close()
	host := strings.TrimPrefix(site.URL, "http://")
	tmp := func(n string) string { return filepath.Join(t.TempDir(), n) }
	for name, args := range map[string][]string{
		"shots":        {"shots", "-u", site.URL + "/", "-dir", tmp("s"), "-db", tmp("s.db")},
		"run -browser": {"run", "-url", site.URL + "/", "-browser", "-db", tmp("r.db")},
		"crawl":        {"crawl", "-u", site.URL + "/", "-browser", "-db", tmp("c.db")},
		"run -login":   {"run", "-url", site.URL + "/", "-login", site.URL + "/", "-login-user", "u", "-login-pass", "p", "-db", tmp("l.db")},
		"roles": {"roles", "-dir", tmp("roles"), "-login", site.URL + "/", "-role", "anon", "-role-login", "u=u:p", "--",
			"-url", site.URL + "/", "-allow", host, "-no-paths", "-depth", "0"},
	} {
		asked.Store(0)
		_, errOut, code := cli(t, append(args, "-json")...)
		if code != exitUsage || !strings.Contains(errOut, "-chrome-no-sandbox") {
			t.Errorf("%s: exit %d, want %d naming -chrome-no-sandbox:\n%s", name, code, exitUsage, errOut)
		}
		if asked.Load() != 0 {
			t.Errorf("%s: %d requests reached the target before Chrome was refused", name, asked.Load())
		}
	}

	// -chrome-no-sandbox allows it, and the summary says Chrome ran without.
	_, errOut, code := cli(t, "shots", "-u", site.URL+"/", "-dir", tmp("s2"), "-db", tmp("s2.db"), "-chrome-no-sandbox", "-json")
	if code != exitOK && code != exitPartial {
		t.Fatalf("shots -chrome-no-sandbox: exit %d\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "Chrome ran without its sandbox") {
		t.Errorf("the summary does not say Chrome ran without its sandbox:\n%s", errOut)
	}

	if strings.Contains(errOut, "Chrome ran with its sandbox") {
		t.Errorf("the summary says both modes:\n%s", errOut)
	}

	// -chrome-require-sandbox is still accepted, and cannot go with the opt-in.
	_, errOut, code = cli(t, "shots", "-u", site.URL+"/", "-dir", tmp("s3"), "-db", tmp("s3.db"), "-chrome-require-sandbox", "-chrome-no-sandbox", "-json")
	if code != exitUsage || !strings.Contains(errOut, "contradict") {
		t.Errorf("both flags: exit %d\n%s", code, errOut)
	}
	_, errOut, code = cli(t, "shots", "-u", site.URL+"/", "-dir", tmp("s4"), "-db", tmp("s4.db"), "-chrome-require-sandbox", "-json")
	if code != exitUsage || !strings.Contains(errOut, "-chrome-no-sandbox") {
		t.Errorf("-chrome-require-sandbox alone: exit %d\n%s", code, errOut)
	}
}

// azhaq mcp holds the opt-in for the commands its tools run.
func TestMCPHoldsChromeNoSandbox(t *testing.T) {
	if got := (heldRun{ChromeNoSandbox: true}).options("run"); !strings.Contains(strings.Join(got, " "), "-chrome-no-sandbox") {
		t.Errorf("run options: %v", got)
	}
	if got := (heldRun{}).options("run"); strings.Contains(strings.Join(got, " "), "-chrome-no-sandbox") {
		t.Errorf("run options without it: %v", got)
	}
}

// The summary names the mode Chrome ran in, so a reader need not read ps (a
// sandboxed Chrome still starts a --no-zygote-sandbox zygote for its GPU
// process): "Chrome ran with its sandbox" or "Chrome ran without its
// sandbox", and neither when Chrome never started.
func TestSummaryNamesTheModeChromeRanIn(t *testing.T) {
	t.Setenv("AZHAQ_CHROME_NO_SANDBOX", "")
	t.Setenv("AZHAQ_CHROME", "")
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>home</title><a href="/a">a</a></html>`)
	}))
	defer site.Close()
	tmp := func(n string) string { return filepath.Join(t.TempDir(), n) }
	_, errOut, code := cli(t, "shots", "-u", site.URL+"/", "-dir", tmp("s"), "-db", tmp("s.db"), "-json")
	if code == exitUsage && strings.Contains(errOut, "-chrome-no-sandbox") {
		t.Skip("this system gives Chrome no sandbox")
	}
	if code != exitOK && code != exitPartial {
		t.Fatalf("shots: exit %d\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "Chrome ran with its sandbox") || strings.Contains(errOut, "without its sandbox") {
		t.Errorf("the summary does not say Chrome ran with its sandbox:\n%s", errOut)
	}
	_, errOut, code = cli(t, "run", "-url", site.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-depth", "0", "-no-paths", "-db", tmp("r.db"), "-json")
	if code != exitOK && code != exitPartial {
		t.Fatalf("run: exit %d\n%s", code, errOut)
	}
	if strings.Contains(errOut, "Chrome ran") {
		t.Errorf("a run that started no Chrome names a mode:\n%s", errOut)
	}
}
