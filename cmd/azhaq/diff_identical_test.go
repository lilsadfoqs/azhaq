package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// Two runs of the same unchanged app diff empty. A catch-all row carries the
// request it was compared with, whose path is random in each run; what the
// control proved (its answer) is compared, not the name it was asked for.
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
}
