package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// At -depth 0 the answer for api (a CNAME to www with www's address) is the
// only DNS the run does, and www was never looked up itself: it is still a
// live name with the address that answer held, not "unresolved".
func TestCNAMETargetAtDepthZeroHoldsItsAddress(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	words := writeList(t, "api")
	_, errOut, code := cli(t, "run", "-domain", "lab.zz", "-dns-brute", words, "-sources", "none", "-resolvers", lab.addr,
		"-allow", "lab.zz", "-web-ports", "65534", "-no-paths", "-no-favicon", "-no-tech", "-no-follow", "-no-takeover",
		"-depth", "0", "-db", "b.db", "-quiet")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	out, _, err := captureBoth(t, func() error {
		return run([]string{"query", "-db", "b.db", "-type", "Hostname", "-fields", "key,role,proof", "-json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range lines(out) {
		var row map[string]string
		if json.Unmarshal([]byte(l), &row) != nil || row["key"] != "www.lab.zz" {
			continue
		}
		found = true
		if row["role"] != "live" || !strings.Contains(row["proof"], "ips=[192.0.2.1]") {
			t.Errorf("www.lab.zz: role %q, proof %q; want live with ips=[192.0.2.1]", row["role"], row["proof"])
		}
	}
	if !found {
		t.Errorf("no row for www.lab.zz:\n%s", out)
	}
}
