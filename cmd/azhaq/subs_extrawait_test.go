package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// subs stops waiting for the sources outside subfinder's default set
// -extra-wait after the others have answered: the names the others gave are
// printed at once and the slow one is listed as failed, with the reason.
func TestSubsExtraWaitCutsASlowExtraSource(t *testing.T) {
	t.Chdir(t.TempDir())
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "core", Default: true, Names: []string{"www.example.org"}},
		subcol.TestSource{Name: "slowextra", Default: true, Extra: true, Names: []string{"late.example.org"}, Delay: time.Minute},
	)()
	t0 := time.Now()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-extra-wait", "200ms", "-no-history")
	if took := time.Since(t0); took > 10*time.Second {
		t.Fatalf("subs took %s: the extra source held it", took)
	}
	if code != exitOK || !strings.Contains(out, "www.example.org") {
		t.Fatalf("exit %d out %q", code, out)
	}
	if rep.Counts["sources failed"] != 1 || !rep.Degraded {
		t.Errorf("the cut source is a failed source of the summary: %v degraded %v", rep.Counts, rep.Degraded)
	}
	if !strings.Contains(rep.Sources.FailedSources["slowextra"], "-extra-wait") {
		t.Errorf("the summary does not say why it was cut: %+v", rep.Sources)
	}
}

func TestExtraWaitIsNotNegative(t *testing.T) {
	t.Chdir(t.TempDir())
	_, _, code := runContract(t, "subs", "-d", "example.org", "-extra-wait", "-1s", "-no-history")
	if code != exitUsage {
		t.Errorf("exit %d", code)
	}
}
