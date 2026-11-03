package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/guard"
	"github.com/lilsadfoqs/azhaq/types"
)

func exitOf(t *testing.T, strict bool, build func(r *report)) *report {
	t.Helper()
	was := strictExit
	strictExit = strict
	t.Cleanup(func() { strictExit = was })
	r := newReport("run")
	build(r)
	r.settle()
	return r
}

func fail(collector, err string, targets ...string) engine.Failure {
	return engine.Failure{Collector: collector, Error: err, Count: max(len(targets), 1), Targets: targets}
}

// One rule for every command: a run that did its job exits 0 and names its
// failures; a run whose job failed exits 3; a limit exits 4; -strict-exit
// makes any failure exit 3.
func TestExitRule(t *testing.T) {
	cases := []struct {
		name     string
		strict   bool
		build    func(r *report)
		exit     int
		failures int
	}{
		{name: "all good", build: func(r *report) { r.units(3, 0) }, exit: exitOK},
		{name: "mixed: one of three failed", build: func(r *report) {
			r.units(3, 1)
			r.Unreachable = []string{"http://c/"}
			r.Failed = []engine.Failure{fail("azhaq-http", "connection refused", "http://c/")}
		}, exit: exitOK, failures: 1},
		{name: "mixed, strict", strict: true, build: func(r *report) {
			r.units(3, 1)
			r.Unreachable = []string{"http://c/"}
			r.Failed = []engine.Failure{fail("azhaq-http", "connection refused", "http://c/")}
		}, exit: exitPartial, failures: 1},
		{name: "all failed", build: func(r *report) {
			r.units(2, 2)
			r.Unreachable = []string{"http://a/", "http://b/"}
			r.Failed = []engine.Failure{fail("azhaq-http", "connection refused", "http://a/", "http://b/")}
		}, exit: exitPartial, failures: 2},
		{name: "limited", build: func(r *report) {
			r.units(3, 1)
			r.Failed = []engine.Failure{fail("azhaq-http", "timeout", "http://c/")}
			r.Stopped = "the request budget of 5 is spent"
		}, exit: exitLimit, failures: 1},
		{name: "a failure that names no target is the run's own", build: func(r *report) {
			r.units(3, 0)
			r.Failed = []engine.Failure{{Collector: "azhaq-session", Error: "the session ended", Count: 1}}
		}, exit: exitPartial, failures: 1},
		{name: "a bug fails the run wherever it hit", build: func(r *report) {
			r.units(3, 0)
			r.Failed = []engine.Failure{fail("azhaq-js", guard.Prefix+"boom", "http://a/app.js")}
		}, exit: exitPartial, failures: 1},
		{name: "a note that says the results are short", build: func(r *report) {
			r.units(3, 0)
			r.warned = true
		}, exit: exitPartial},
		{name: "nothing countable: any failure exits 3", build: func(r *report) {
			r.Failed = []engine.Failure{fail("azhaq-portscan", "timeout", "192.0.2.1:80")}
		}, exit: exitPartial, failures: 1},
		{name: "a fan-out failure alone", build: func(r *report) {
			r.units(1, 0)
			f := fail("azhaq-subdomains", "timeout", "cdn.example")
			f.Fanout = true
			r.Failed = []engine.Failure{f}
		}, exit: exitOK, failures: 1},
		{name: "a probe row without an answer, among answers", build: func(r *report) {
			n := 1
			r.failedRows = &n
			r.units(4, 1)
		}, exit: exitOK, failures: 1},
		{name: "every probe row without an answer", build: func(r *report) {
			n := 2
			r.failedRows = &n
			r.units(2, 2)
		}, exit: exitPartial, failures: 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exitOf(t, c.strict, c.build)
			if r.Exit != c.exit || r.Failures != c.failures {
				t.Errorf("exit %d failures %d, want %d and %d", r.Exit, r.Failures, c.exit, c.failures)
			}
			if r.Complete != (r.Exit == exitOK) {
				t.Errorf("complete %v with exit %d", r.Complete, r.Exit)
			}
		})
	}
}

// What a run was given is counted from its seeds: a URL fails when it is
// unreachable, a domain when no third-party source answered for it, and the
// collector that does a command's job on a page fails the page.
func TestTallySeeds(t *testing.T) {
	seeds := []types.Seed{
		{Type: types.TypeURL, Keys: map[string]string{"url": "http://a/"}},
		{Type: types.TypeURL, Keys: map[string]string{"url": "http://b/"}},
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "x.example"}},
		{Type: types.TypeDomain, Keys: map[string]string{"domain": "y.example"}},
		{Type: types.TypePrefix, Keys: map[string]string{"prefix": "192.0.2.0/24"}},
	}
	failed := []engine.Failure{
		fail("azhaq-subdomains", "timeout", "x.example"),
		{Collector: "azhaq-subdomains", Error: "timeout", Count: 1, Targets: []string{"y.example"}, Partial: true},
		fail("azhaq-params", "HTTP 429", "http://a/"),
	}
	if got := tallySeeds("run", seeds, []string{"http://b/"}, failed); got != (targetTally{4, 2}) {
		t.Errorf("run: %+v, want 4 given, 2 failed", got)
	}
	if got := tallySeeds("params", seeds, []string{"http://b/"}, failed); got != (targetTally{4, 3}) {
		t.Errorf("params: %+v, want 4 given, 3 failed", got)
	}
}

// fuzz: a request that fails is a failure of the target, counted in
// failures; the run exits 0 while some inputs were answered, 3 when none
// was, and 3 for any failure with -strict-exit.
func TestFuzzExitRule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/bad") || strings.HasSuffix(r.URL.Path, "/worse") {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	words := func(ws ...string) string { return wlist(t, ws...) }
	for _, c := range []struct {
		name   string
		words  []string
		extra  []string
		exit   int
		failed int
	}{
		{name: "all answered", words: []string{"a", "b"}, exit: exitOK},
		{name: "mixed", words: []string{"a", "bad"}, exit: exitOK, failed: 1},
		{name: "mixed, strict", words: []string{"a", "bad"}, extra: []string{"-strict-exit"}, exit: exitPartial, failed: 1},
		{name: "all failed", words: []string{"bad", "worse"}, exit: exitPartial, failed: 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			was := strictExit
			t.Cleanup(func() { strictExit = was })
			strictExit = false
			_, rep, err := fuzzRows(t, append([]string{"-u", srv.URL + "/FUZZ", "-w", words(c.words...), "-mc", "all"}, c.extra...)...)
			if exitCode(err) != c.exit || rep.Exit != c.exit || rep.Failures != c.failed || rep.Complete != (c.exit == exitOK) {
				t.Errorf("exit %d (summary %d), failures %d, complete %v; want exit %d, failures %d", exitCode(err), rep.Exit, rep.Failures, rep.Complete, c.exit, c.failed)
			}
		})
	}
}

// An internal error (the summary disagrees with its rows) is exit 1 whatever
// the run's outcome; `failures` and `error` are separate fields.
func TestAnInternalErrorComesBeforeTheExitRule(t *testing.T) {
	for _, strict := range []bool{false, true} {
		r := exitOf(t, strict, func(r *report) {
			r.units(3, 1) // a run that did its job, with one failure
			r.Failed = []engine.Failure{fail("azhaq-http", "connection refused", "http://c/")}
			r.Results = 5
			r.emitted().add("", 1) // one row emitted, five published
		})
		if r.Exit != exitError || r.Complete || r.Error == "" || r.Failures != 1 {
			t.Errorf("strict %v: exit %d, complete %v, error %q, failures %d; want exit 1, not complete, an error and 1 failure", strict, r.Exit, r.Complete, r.Error, r.Failures)
		}
	}
	// Stopped by a limit, the same: the error wins.
	r := exitOf(t, false, func(r *report) {
		r.Stopped = "the request budget is spent"
		r.Results = 2
		r.emitted().add("", 1)
	})
	if r.Exit != exitError {
		t.Errorf("a limit with an internal error: exit %d, want 1", r.Exit)
	}
}
