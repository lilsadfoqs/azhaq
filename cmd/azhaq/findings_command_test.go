package main

import (
	"strings"
	"testing"
)

// The command a finding carries reproduces its run: run's own flags get the
// command name, which the workspace keeps only for dns, fuzz and ingest.
func TestFindingCommandNamesTheCommand(t *testing.T) {
	for args, want := range map[string]string{
		"-url http://127.0.0.1:5013/ -graphql": "azhaq run -url http://127.0.0.1:5013/ -graphql",
		"dns -d example.test":                  "azhaq dns -d example.test",
	} {
		got := runCommand(&graphView{args: strings.Fields(args)})
		if got != want {
			t.Errorf("args %q: command %q, want %q", args, got, want)
		}
		name := strings.Fields(got)[1]
		known := false
		for _, c := range commands {
			known = known || c.name == name
		}
		if !known {
			t.Errorf("%q does not start with a command", got)
		}
	}
}
