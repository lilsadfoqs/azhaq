package main

import (
	"strings"
	"testing"
	"time"
)

// Every command that sends takes the egress flags of its kind, from the
// shared registration: the resolvers, the ledger and its seal, the scope, the
// pace and the budget.
func TestEgressFlagsOnEveryCommandThatSends(t *testing.T) {
	web := []string{"resolvers", "ledger", "seal-to", "proxy", "allow", "deny", "deny-path", "rate", "max-requests"}
	for cmd, want := range map[string][]string{
		"run": web, "plan": web, "probe": web, "crawl": web, "dirs": web, "params": web, "shots": web, "urls": web, "fuzz": web,
		"roles": {"resolvers", "seal-to", "proxy", "allow", "deny", "deny-path", "rate"},
		"ports": {"resolvers", "ledger", "seal-to", "proxy", "allow", "deny", "rate", "max-requests"},
		"dns":   {"resolvers", "ledger", "seal-to", "proxy", "allow", "deny"},
		"mcp":   {"resolvers", "proxy", "chrome-proxy", "allow", "deny", "deny-path", "rate", "max-requests"},
		"subs":  {"resolvers", "ledger", "seal-to", "proxy", "allow", "deny"},
	} {
		fs := flagsOf(cmd)
		if fs == nil {
			t.Fatalf("%s: no flags", cmd)
		}
		var missing []string
		for _, f := range want {
			if fs.Lookup(f) == nil {
				missing = append(missing, "-"+f)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s lacks %s", cmd, strings.Join(missing, " "))
		}
	}
}

// plan takes a target as written, as azhaq TARGET does.
func TestPlanTakesATargetAsWritten(t *testing.T) {
	out, errOut, code := cli(t, "plan", "http://127.0.0.1:3001/", "-sources", "none")
	if code != exitOK || !strings.Contains(out, "URL http://127.0.0.1:3001/") {
		t.Errorf("exit %d:\n%s\n%s", code, out, errOut)
	}
	if _, _, code := cli(t, "plan", "not a target"); code != exitUsage {
		t.Errorf("a word that is no target: exit %d, want %d", code, exitUsage)
	}
}

// dns -maxtime takes a duration, as run's -max-time does, and still a bare
// number of seconds.
func TestDNSMaxtimeTakesADurationOrSeconds(t *testing.T) {
	for v, want := range map[string]time.Duration{"90": 90 * time.Second, "1.5": 1500 * time.Millisecond, "5m": 5 * time.Minute, "250ms": 250 * time.Millisecond} {
		var d secondsOrDuration
		if err := d.Set(v); err != nil || time.Duration(float64(d)*float64(time.Second)) != want {
			t.Errorf("%s: %v %v", v, time.Duration(float64(d)*float64(time.Second)), err)
		}
	}
	var d secondsOrDuration
	if d.Set("soon") == nil || d.Set("-1") == nil {
		t.Error("a word or a negative time is taken")
	}
}
