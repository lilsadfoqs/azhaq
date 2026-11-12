package main

import (
	"strings"
	"testing"
)

// -chrome-no-sandbox is a run option: before -- roles says to put it after.
func TestRolesRunOptionBeforeDoubleDashSaysWhereItGoes(t *testing.T) {
	err := cmdRoles([]string{"-chrome-no-sandbox", "-role", "anon", "--", "-url", "http://127.0.0.1:1/"})
	if exitCode(err) != exitUsage || err == nil || !strings.Contains(err.Error(), "-chrome-no-sandbox is a run option") || !strings.Contains(err.Error(), "after --") {
		t.Errorf("%v", err)
	}
	// A flag nobody has keeps the flag package's words.
	err = cmdRoles([]string{"-nonesuch-flag", "-role", "anon"})
	if err == nil || strings.Contains(err.Error(), "run option") {
		t.Errorf("%v", err)
	}
	out, _ := captureStdout(t, func() error { return cmdRoles([]string{"-h"}) })
	if !strings.Contains(out, "-chrome-no-sandbox among the run options, after --") {
		t.Errorf("roles -h does not say where -chrome-no-sandbox goes:\n%s", out)
	}
}
