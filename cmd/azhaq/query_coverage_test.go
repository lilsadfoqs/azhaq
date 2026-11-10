package main

import (
	"strings"
	"testing"
)

// query -coverage refuses a value no row can have, as export does, and names
// the values it takes.
func TestQueryRefusesAnUnknownCoverage(t *testing.T) {
	db := coverageDB(t)
	_, errOut, code := cli(t, "query", "-db", db, "-coverage", "visitd")
	if code != exitUsage || !strings.Contains(errOut, `-coverage "visitd": use visited, catchall, error, gone, hint, skipped, capped`) {
		t.Errorf("exit %d\n%s", code, errOut)
	}
	if _, _, code = cli(t, "query", "-db", db, "-coverage", "visited,gone"); code != exitOK {
		t.Errorf("known coverages: exit %d", code)
	}
	if _, _, code = cli(t, "query", "-db", db, "-coverage", "Capped"); code != exitOK {
		t.Errorf("a coverage in capitals: exit %d", code)
	}
}
