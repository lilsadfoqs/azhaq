package main

import (
	"strings"
	"sync/atomic"
	"testing"

	"net/http"
	"net/http/httptest"
)

// A flag that takes a value, followed by another flag, is a usage error
// before anything is sent: -screenshots would take "-max-requests" for its
// directory, and the cap would never be set.
func TestFlagThatTakesAValueDoesNotEatTheNextFlag(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	cases := []struct {
		name string
		run  func([]string) error
		args []string
	}{
		{"run -screenshots", cmdRun, []string{"-url", srv.URL + "/", "-screenshots", "-max-requests", "50", "-db", dir + "/a.db"}},
		{"run -screenshots, a flag with a value", cmdRun, []string{"-url", srv.URL + "/", "-screenshots", "-max-requests=50", "-db", dir + "/b.db"}},
		{"fuzz -w", cmdFuzz, []string{"-u", srv.URL + "/FUZZ", "-w", "-mc", "all"}},
		{"double dash", cmdFuzz, []string{"-u", srv.URL + "/FUZZ", "--w", "-mc", "all"}},
	}
	for _, c := range cases {
		_, _, err := captureBoth(t, func() error { return c.run(c.args) })
		if exitCode(err) != exitUsage || err == nil || !strings.Contains(err.Error(), "needs a value") {
			t.Errorf("%s: exit %d, %v", c.name, exitCode(err), err)
		}
	}
	if n.Load() != 0 {
		t.Errorf("%d requests were sent", n.Load())
	}
}

// A value that starts with a dash is still given as -flag=-value, and a
// dash alone (stdin), a number and a value that is no flag of the command
// are values as before.
func TestFlagValuesThatLookLikeFlagsStillWork(t *testing.T) {
	fs := flagsOf("fuzz")
	for _, args := range [][]string{
		{"-w", "-"},
		{"-w=-mc", "-mc", "all"},
		{"-H", "-x: y", "-mc", "all"},
		{"-rate", "-1"},
		{"-u", "http://x/FUZZ", "--", "-w", "-mc"},
		{"-json", "-mc", "all"}, // a bool flag takes none
	} {
		if err := flagEatsFlag(fs, args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}
