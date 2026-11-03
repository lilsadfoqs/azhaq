package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// finishCaptured prints rep's summary under -json and returns what it wrote
// to stderr and the error it gave.
func finishCaptured(t *testing.T, rep *report) (string, error) {
	t.Helper()
	var err error
	errOut := captureStderr(t, func() { err = rep.finish(true, false) })
	return errOut, err
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// A summary that disagrees with its rows is never reported as done: exit 1,
// a message of its own, complete false.
func TestASummaryThatDisagreesWithItsRowsIsAnInternalError(t *testing.T) {
	for _, c := range []struct {
		name string
		make func() *report
		want string
	}{
		{"the counts do not add up to the stored rows", func() *report {
			r := newReport("run")
			folded := 0
			r.Folded, r.Stored, r.Results, r.Counts = &folded, 5, 5, map[string]int{"pages": 4}
			return r
		}, "the counts added together"},
		{"results are not the rows printed", func() *report {
			r := newReport("run")
			folded := 0
			r.Folded, r.Stored, r.Results, r.Counts = &folded, 2, 2, map[string]int{"pages": 2}
			r.emitted().add("pages", 1)
			return r
		}, "results, against the rows emitted"},
		{"a count is not what the rows give", func() *report {
			r := newReport("roles")
			r.Results, r.Counts = 2, map[string]int{"cross": 1, "shared": 1}
			r.emitted().add("cross", 1)
			r.emitted().add("cross", 1)
			return r
		}, "count cross"},
		{"a number a command states for its own rows", func() *report {
			r := newReport("crawl")
			r.holds("the URL rows counted by class, against the rows listed and the rows left out", 149, 148)
			return r
		}, "the summary says 149, the rows say 148"},
	} {
		t.Run(c.name, func(t *testing.T) {
			errOut, err := finishCaptured(t, c.make())
			if exitCode(err) != exitError {
				t.Fatalf("exit %d, want %d", exitCode(err), exitError)
			}
			if msg := err.Error(); !strings.Contains(msg, "internal error") || !strings.Contains(msg, c.want) {
				t.Errorf("message %q: no internal error naming %q", msg, c.want)
			}
			rep := lastReport(t, errOut)
			if rep.Complete || rep.Exit != exitError || !strings.Contains(rep.Error, "internal error") {
				t.Errorf("summary complete %v, exit %d, error %q", rep.Complete, rep.Exit, rep.Error)
			}
		})
	}
}

// A summary that agrees with its rows is as it was.
func TestASummaryThatAgreesWithItsRowsIsComplete(t *testing.T) {
	r := newReport("run")
	folded := 1
	r.Folded, r.Stored, r.Results, r.Counts = &folded, 3, 2, map[string]int{"pages": 2, "api": 1}
	r.emitted().add("pages", 1)
	r.emitted().add("", 2)
	if _, err := finishCaptured(t, r); err != nil {
		t.Fatalf("a summary that adds up gave %v", err)
	}
}

// crawl without -json lists a row a GET can ask and leaves out the routes
// with a parameter and the views: the summary counts the rows it listed and
// the rows it said it left out, and they are every row counted by class.
func TestPlainCrawlHintsAndTheRowsLeftOutAddUp(t *testing.T) {
	srv := kindsSite(t)
	out, errOut := crawlOut(t, srv, "-hints")
	listed := strings.Count(strings.TrimSpace(out), "\n") + 1
	var classes, leftOut int
	for _, k := range []string{"observed routes", "linked routes", "hint routes", "named strings"} {
		classes += countIn(t, errOut, k)
	}
	for _, k := range []string{"left out as not URLs", "left out by the extension list"} {
		leftOut += countIn(t, errOut, k)
	}
	if classes != listed+leftOut {
		t.Errorf("%d rows counted by class, %d listed and %d said to be left out:\n%s\n%s", classes, listed, leftOut, out, errOut)
	}
	if !strings.Contains(errOut, "no URL to request") {
		t.Errorf("the summary does not say why a row was left out of the list:\n%s", errOut)
	}
}

// countIn is the number written before name in a plain summary's counts, 0 when absent.
func countIn(t *testing.T, summary, name string) int {
	t.Helper()
	i := strings.Index(summary, " "+name)
	if i < 0 {
		return 0
	}
	j := i
	for j > 0 && summary[j-1] >= '0' && summary[j-1] <= '9' {
		j--
	}
	n := 0
	for _, ch := range summary[j:i] {
		n = n*10 + int(ch-'0')
	}
	return n
}
