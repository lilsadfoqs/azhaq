package main

import (
	"strings"
	"testing"
)

// portsOnRun says, for each flag of ports that run lacks under that name,
// what run takes instead (a twin: the flag must exist on run) or why none
// belongs there. A new ports flag is in neither place until someone decides,
// and this test fails until they do.
var portsOnRun = map[string]string{
	// run's twins, as the port stage of a run names them
	"p": "twin:ports", "tp": "twin:ports", "pf": "twin:ports", "ep": "twin:port-skip", "pu": "twin:ports-udp", "udp": "twin:ports-udp",
	"min-rate": "twin:port-min-rate", "workers": "twin:port-workers", "c": "twin:port-workers",
	"retries": "twin:port-retries", "max-retries": "twin:port-retries", "order": "twin:port-order", "seed": "twin:port-seed",
	"unnamed": "twin:port-unnamed", "detect": "twin:port-detect", "pts": "twin:port-threshold", "iv": "twin:port-ip", "sa": "twin:port-all-ips",
	"exclude-cdn": "twin:port-exclude-cdn", "ec": "twin:port-exclude-cdn", "cdn-full": "twin:port-cdn-full",
	"sn": "twin:port-discover", "wn": "twin:port-discover", "source-ip": "twin:port-source-ip", "cp": "twin:port-payload",
	"proxy-auth": "twin:port-proxy-auth", "eh": "twin:deny", "r": "twin:resolvers",
	// not on run, deliberately
	"host":     "not: run's targets are -url, -domain, -cidr, -asn and -list",
	"l":        "not: run's file of targets is -list",
	"no-stdin": "not: run reads stdin only for -list -",
	"ef":       "not: a file of exclusions; run's -deny is repeatable",
	"T":        "not: a shorthand for -rate, -connect-timeout and -retries, which run takes (-port-rate, -connect-timeout, -port-retries)",
	"Pn":       "not: naabu's no-op, accepted by ports only",
	"cdn":      "not: naabu's no-op, accepted by ports only",
	"nc":       "not: naabu's no-op, accepted by ports only",
	"oX":       "not: ports' own output formats; run writes the workspace and its own rows",
	"oG":       "not: ports' own output formats",
	"oA":       "not: ports' own output formats",
	"csv":      "not: ports' own output format",
	"eof":      "not: fields of ports' rows",
	"lof":      "not: lists the fields of ports' rows",
	"udp-rows": "not: how ports prints its UDP rows",
	"silent":   "not: ports' output only",
	"j":        "not: ports' alias of -json",
}

// Every flag ports registers is accepted by run, has a twin on run, or is
// listed above as deliberately not there, so a gap such as run's missing
// -connect-timeout cannot reopen.
func TestEveryPortsFlagIsOnRunOrListed(t *testing.T) {
	flags := map[string]map[string]bool{}
	for _, c := range buildManifest().Commands {
		set := map[string]bool{}
		for _, f := range c.Flags {
			set[f.Name] = true
		}
		flags[c.Name] = set
	}
	for name := range flags["ports"] {
		why, listed := portsOnRun[name]
		switch {
		case flags["run"][name] && !listed:
		case flags["run"][name]:
			if why != "" {
				t.Errorf("-%s is on run: drop it from portsOnRun", name)
			}
		case !listed:
			t.Errorf("ports has -%s and run has not: add it to run, or to portsOnRun with the reason", name)
		case strings.HasPrefix(why, "twin:"):
			if twin := strings.TrimPrefix(why, "twin:"); !flags["run"][twin] {
				t.Errorf("-%s is listed with run's -%s, which run has not", name, twin)
			}
		case !strings.HasPrefix(why, "not: "):
			t.Errorf("-%s: %q is no twin: and no not: reason", name, why)
		}
	}
	for name := range portsOnRun {
		if !flags["ports"][name] {
			t.Errorf("portsOnRun lists -%s, which ports has not", name)
		}
	}
	for _, cmd := range []string{"run", "plan"} {
		if !flags[cmd]["connect-timeout"] {
			t.Errorf("%s has no -connect-timeout", cmd)
		}
	}
}

// run, plan and resume take ports' -connect-timeout, with its bare number
// in milliseconds, and it reaches the port stage: a negative wait is refused
// by the port config, as -port-timeout's is.
func TestConnectTimeoutReachesTheRunsPortStage(t *testing.T) {
	srv, _ := spaStandIn(t)
	db := t.TempDir() + "/c.db"
	for _, flag := range []string{"-connect-timeout", "-port-timeout"} {
		_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-ports", "1", flag, "-1s", "-db", db, "-ledger", "off", "-json")
		if code != exitUsage || !strings.Contains(errOut, "-port-timeout, -port-workers and -port-threshold are not negative") {
			t.Errorf("%s -1s: exit %d, stderr %q: want the port config's usage error", flag, code, errOut)
		}
	}
	_, errOut, code := cli(t, "plan", "-url", srv.URL+"/", "-ports", "22", "-connect-timeout", "1500", "-json")
	if code != exitOK {
		t.Errorf("plan -connect-timeout 1500: exit %d: %s", code, errOut)
	}
	_, errOut, code = cli(t, "plan", "-url", srv.URL+"/", "-ports", "22", "-connect-timeout", "-1s", "-json")
	if code != exitUsage {
		t.Errorf("plan -connect-timeout -1s: exit %d, want a usage error: %s", code, errOut)
	}
	_, errOut, code = cli(t, "run", "-url", srv.URL+"/", "-ports", "1", "-connect-timeout", "soon", "-db", db, "-ledger", "off", "-json")
	if code != exitUsage || !strings.Contains(errOut, "connect-timeout") {
		t.Errorf("-connect-timeout soon: exit %d, stderr %q", code, errOut)
	}
}

// resume takes -connect-timeout like any run option, and a flag it does not
// know is still refused.
func TestResumeTakesConnectTimeout(t *testing.T) {
	srv, _ := spaStandIn(t)
	t.Chdir(t.TempDir())
	db := t.TempDir() + "/s.db"
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-max-requests", "8", "-json")
	if code != exitLimit {
		t.Fatalf("first run: exit %d: %s", code, errOut)
	}
	if _, errOut, code = cli(t, "resume", "-db", db, "-connect-timeout", "-1s", "-max-requests", "0"); code != exitUsage {
		t.Errorf("resume -connect-timeout -1s: exit %d, want a usage error: %s", code, errOut)
	}
	if _, errOut, code = cli(t, "resume", "-db", db, "-connect-timeout", "2s", "-max-requests", "0"); code != exitOK {
		t.Errorf("resume -connect-timeout 2s: exit %d: %s", code, errOut)
	}
}
