package main

import (
	"os"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// The name history (subcol) is per user: tests keep theirs in a temp dir.
func TestMain(m *testing.M) {
	// Tests that start Chrome run where the system may give it no sandbox: this
	// is the user's say (also for the commands run again as a process) that it
	// may run without one. A test of the refusal clears it.
	os.Setenv("AZHAQ_CHROME_NO_SANDBOX", "1")
	// Tests never keep runs in the user's home; a test of the run home sets its own.
	if os.Getenv("AZHAQ_HOME") == "" {
		os.Setenv("AZHAQ_HOME", "none")
	}
	if os.Getenv("AZHAQ_TEST_AS_MAIN") == "1" {
		if names := os.Getenv("AZHAQ_TEST_SUBS_NAMES"); names != "" {
			// A subs run in its own process, on one source that gives these names.
			subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: strings.Split(names, ",")})
		}
		main() // a test that needs the process, with its real stderr, runs this binary again
	}
	dir, err := os.MkdirTemp("", "azhaq-test-data-")
	if err != nil {
		panic(err)
	}
	os.Setenv("AZHAQ_DATA_DIR", dir)
	subcol.DatabaseOff() // no test reaches crt.sh
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
