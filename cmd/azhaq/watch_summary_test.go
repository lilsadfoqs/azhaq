package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The last summary of a watch that notified is the process's outcome: the
// run's complete, exit, stopped and requests, a failed delivery or
// -notify-cmd making it 3, and the notifications' own count in results. It
// is named notify, as the command's own summary of a message is, and no
// summary after the run's says complete with exit 0 when the process did not.
func TestWatchLastSummaryIsTheProcessOutcome(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var links strings.Builder
		for i := range 12 {
			fmt.Fprintf(&links, `<a href="/p%d">p</a>`, i)
		}
		fmt.Fprint(w, "<html><title>site</title><body>"+links.String()+"</body></html>")
	}))
	defer site.Close()
	var posts atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts.Add(1) }))
	defer hook.Close()
	for _, c := range []struct {
		name      string
		run, more []string
		exit      int
		stopped   bool
		noHook    bool // -notify-cmd alone
	}{
		{"a run that hit its request cap", []string{"-max-requests", "3"}, nil, exitLimit, true, false},
		{"a complete run", []string{"-no-paths", "-depth", "0", "-probe"}, nil, exitOK, false, false},
		{"a complete run, -notify-cmd fails", []string{"-no-paths", "-depth", "0", "-probe"}, []string{"-notify-cmd", "exit 7"}, exitPartial, false, false},
		{"a capped run, -notify-cmd fails", []string{"-max-requests", "3"}, []string{"-notify-cmd", "exit 7"}, exitLimit, true, false},
		{"a complete run, only a failing -notify-cmd", []string{"-no-paths", "-depth", "0", "-probe"}, []string{"-notify-cmd", "exit 7"}, exitPartial, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			posts.Store(0)
			db := filepath.Join(t.TempDir(), "w.db")
			args := []string{"-db", db, "-json", "-always", "-notify-rate", "0"}
			if !c.noHook {
				args = append(args, "-notify", hook.URL+"/n")
			}
			args = append(args, c.more...)
			args = append(append(args, "--", "-url", site.URL+"/", "-allow", "127.0.0.1"), c.run...)
			_, errOut, err := captureBoth(t, func() error { return cmdWatch(args) })
			if exitCode(err) != c.exit {
				t.Fatalf("the process exits %d, want %d\n%s", exitCode(err), c.exit, errOut)
			}
			var sums []report
			for _, l := range strings.Split(errOut, "\n") {
				if strings.HasPrefix(l, "{") && strings.Contains(l, `"type":"summary"`) {
					sums = append(sums, lastReport(t, l))
				}
			}
			if len(sums) != 2 || sums[0].Command != "run" || sums[1].Command != "notify" {
				t.Fatalf("summaries %d: want the run's, then the notifications'\n%s", len(sums), errOut)
			}
			run, last := sums[0], sums[1]
			if last.Exit != c.exit || last.Complete != (c.exit == exitOK) || (last.Stopped != "") != c.stopped || last.Requests != run.Requests || run.Requests == 0 {
				t.Errorf("last summary exit %d complete %v stopped %q requests %d; the process exits %d and the run said requests %d",
					last.Exit, last.Complete, last.Stopped, last.Requests, c.exit, run.Requests)
			}
			if c.stopped && last.Stopped != run.Stopped {
				t.Errorf("stopped %q, the run's was %q", last.Stopped, run.Stopped)
			}
			if c.noHook != (posts.Load() == 0) || last.Results != int(posts.Load()) {
				t.Errorf("the receiver got %d requests, the summary's results say %d", posts.Load(), last.Results)
			}
		})
	}
}
