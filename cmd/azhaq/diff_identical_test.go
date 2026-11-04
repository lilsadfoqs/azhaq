package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// Two runs of the same unchanged app diff empty. A catch-all row carries the
// request it was compared with: its path is random in each run, and its
// directory is the site root's or the page's own, by which baseline was
// ready first. What the control proved (its answer) is compared, not where
// it was asked.
func TestTwoIdenticalRunsDiffEmpty(t *testing.T) {
	srv, _ := juiceShop(t)
	dbs := [2]string{filepath.Join(t.TempDir(), "a.db"), filepath.Join(t.TempDir(), "b.db")}
	for _, db := range dbs {
		fetch.SetProbeToken(fetch.RandomName()) // a new process picks its own
		args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-quiet", "-db", db}
		if _, errOut, err := captureBoth(t, func() error { return cmdRun(args) }); err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
	}
	out, errOut, err := captureBoth(t, func() error { return printDiff(dbs[0], dbs[1], diffOpts{JSONL: true}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	var sum map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["kind"] == "summary" {
			sum = m
		}
	}
	if sum == nil || sum["added"] != 0.0 || sum["removed"] != 0.0 || sum["observations"] != 0.0 {
		t.Errorf("identical runs differ: %v\n%s", sum, out)
	}
	// watch reads the last two runs of one workspace and must agree.
	ws := filepath.Join(t.TempDir(), "w.db")
	for range 2 {
		fetch.SetProbeToken(fetch.RandomName())
		args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-quiet", "-db", ws}
		if _, errOut, err := captureBoth(t, func() error { return cmdRun(args) }); err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
	}
	ch, err := diffRuns(ws)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Baseline || len(ch.Hosts)+len(ch.Services)+len(ch.URLs)+len(ch.Changed)+len(ch.GoneHosts)+len(ch.GoneSvcs)+len(ch.GoneURLs) != 0 {
		t.Errorf("watch reports a change between two identical runs: %+v", ch)
	}
}
