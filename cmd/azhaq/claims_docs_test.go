package main

import (
	"strings"
	"testing"
)

// -flags and -flags-into take no topic and are not used together; a name that
// is no topic or command is a usage error, exit 2.
func TestDocsFlagsTakeNoTopicAndAnUnknownNameIsAUsageError(t *testing.T) {
	for name, args := range map[string][]string{
		"-flags with a topic":      {"-flags", "ports", "concepts"},
		"-flags-into with a topic": {"-flags-into", t.TempDir(), "concepts"},
		"both together":            {"-flags", "ports", "-flags-into", t.TempDir()},
		"a name that is nothing":   {"nosuchtopic"},
		"a path of nothing":        {"commands/nosuchcommand"},
		"-flags of no command":     {"-flags", "nosuchcommand"},
	} {
		_, _, err := captureBoth(t, func() error { return cmdDocs(args) })
		if exitCode(err) != exitUsage {
			t.Errorf("%s: exit %d (%v), want 2", name, exitCode(err), err)
		}
	}
	for name, args := range map[string][]string{
		"a topic":             {"concepts"},
		"a command":           {"ports"},
		"a command by path":   {"commands/mcp"},
		"-flags of a command": {"-flags", "ports"},
	} {
		out, _, err := captureBoth(t, func() error { return cmdDocs(args) })
		if err != nil || out == "" {
			t.Errorf("%s: %q %v", name, out[:min(len(out), 40)], err)
		}
	}
	// mcp is a topic and a command: the topic comes first, commands/mcp is the page.
	topic, _, _ := captureBoth(t, func() error { return cmdDocs([]string{"mcp"}) })
	page, _, _ := captureBoth(t, func() error { return cmdDocs([]string{"commands/mcp"}) })
	if topic == page || !strings.HasPrefix(page, "# azhaq mcp") {
		t.Errorf("mcp: the topic and the page are the same, or the page is not the command's")
	}
}
