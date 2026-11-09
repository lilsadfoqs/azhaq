package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// A process control page links its actions in the query string (index.html?
// processname=x&action=stop): a crawl holds them back like a /logout, sends the
// links whose parameters name no action, and -send-state-changing sends all.
func TestCrawlHoldsAGetWhoseQueryNamesAnAction(t *testing.T) {
	links := []string{
		"/index.html?processname=x&action=stop",
		"/index.html?processname=x&action=restart",
		"/index.html?cmd=delete",
		"/index.html?action=clear",
	}
	safe := []string{"/index.html?action=view", "/index.html?processname=stop", "/about"}
	run1 := func(flags ...string) (*sweepApp, report) {
		app := newSweepApp(t)
		app.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app.mu.Lock()
			line := "GET " + r.URL.Path
			if r.URL.RawQuery != "" {
				line += "?" + r.URL.RawQuery
			}
			app.got = append(app.got, line)
			app.mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			if r.URL.Path == "/" {
				for _, l := range append(slices.Clone(links), safe...) {
					fmt.Fprintf(w, `<a href="%s">x</a> `, strings.ReplaceAll(l, "&", "&amp;"))
				}
				return
			}
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>ok")
		})
		egress.Reset()
		t.Cleanup(egress.Reset)
		args := append([]string{"run", "-url", app.srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-depth", "3",
			"-db", sweepDB(t), "-ledger", "off", "-json"}, flags...)
		_, errOut, err := captureBoth(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("%v: %s", err, errOut)
		}
		return app, lastReport(t, errOut)
	}
	app, rep := run1()
	for _, l := range links {
		if n := app.count("GET " + l); n != 0 {
			t.Errorf("%s names an action in its query and was sent %d times", l, n)
		}
		held := false
		for _, e := range rep.StateChanging {
			if strings.HasSuffix(e.URL, l) && e.Status == stateHeld && e.Source == "its query" {
				held = true
			}
		}
		if !held {
			t.Errorf("%s is no held row of state_changing from its query: %+v", l, rep.StateChanging)
		}
		listed := false
		for _, s := range rep.Skipped {
			listed = listed || strings.HasSuffix(s.Target, l) && strings.Contains(s.Reason, "-send-state-changing")
		}
		if !listed {
			t.Errorf("%s is not listed under skipped with the flag", l)
		}
	}
	for _, l := range safe {
		if app.count("GET "+l) != 1 {
			t.Errorf("%s names no action and was asked %d times", l, app.count("GET "+l))
		}
	}
	if rep.StateChangingHeld != len(links) {
		t.Errorf("state_changing_held = %d, want %d", rep.StateChangingHeld, len(links))
	}
	app2, rep2 := run1("-send-state-changing")
	for _, l := range links {
		if app2.count("GET "+l) != 1 {
			t.Errorf("-send-state-changing did not send %s", l)
		}
	}
	if rep2.StateChangingHeld != 0 {
		t.Errorf("with the flag %d are held", rep2.StateChangingHeld)
	}
}
