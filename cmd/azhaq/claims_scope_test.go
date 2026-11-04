package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// scope prints how a run would read the scope: the allow and deny rules, the
// domains to enumerate, the targets to probe and the entries that cannot be used.
func TestScopeCommandPrintsHowARunWouldReadIt(t *testing.T) {
	file := scopeFile(t, "*.example.com\napp.example.org:8443\n192.0.2.10\n!legacy.example.com\n")
	out, _, err := captureBoth(t, func() error { return cmdScope([]string{"-scope", file}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3 rules in, 1 out; 1 domains to enumerate, 2 targets to probe as given; 0 entries a run cannot use", "  in    *.example.com", "  out   =legacy.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	js, _, err := captureBoth(t, func() error { return cmdScope([]string{"-scope", file, "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var sc struct {
		Allow, Deny, Domains, Targets, Skipped []string
	}
	if err := json.Unmarshal([]byte(js), &sc); err != nil || len(sc.Allow) != 3 || len(sc.Deny) != 1 || len(sc.Domains) != 1 || len(sc.Targets) != 2 {
		t.Errorf("json %s (%v)", js, err)
	}
	// An entry that cannot be used is listed, and counted.
	file = scopeFile(t, "*.example.com\nAny host verified to be owned by Tesla, such as shop.tesla.com\n")
	out, _, err = captureBoth(t, func() error { return cmdScope([]string{"-scope", file}) })
	if err != nil || !strings.Contains(out, "1 entries a run cannot use") || !strings.Contains(out, "  skip  ") {
		t.Errorf("an entry a run cannot use: %q %v", out, err)
	}
}

// A list of several programs with no -program is an error, exit 1; a scope with
// no in-scope web target is an error, exit 1; with no -scope the command exits 2.
func TestScopeCommandExitCodes(t *testing.T) {
	list := scopeFile(t, `[{"handle":"a","name":"A","url":"https://hackerone.com/a","targets":{"in_scope":[{"asset_identifier":"*.a.com","asset_type":"WILDCARD","eligible_for_submission":true}],"out_of_scope":[]}},
{"handle":"b","name":"B","url":"https://hackerone.com/b","targets":{"in_scope":[{"asset_identifier":"*.b.com","asset_type":"WILDCARD","eligible_for_submission":true}],"out_of_scope":[]}}]`)
	_, _, err := captureBoth(t, func() error { return cmdScope([]string{"-scope", list}) })
	if exitCode(err) != exitError {
		t.Errorf("several programs and no -program: exit %d (%v), want 1", exitCode(err), err)
	}
	if _, _, err := captureBoth(t, func() error { return cmdScope([]string{"-scope", list, "-program", "b"}) }); err != nil {
		t.Errorf("-program b: %v", err)
	}
	empty := scopeFile(t, "# nothing in scope here\n!out.example.com\n")
	_, _, err = captureBoth(t, func() error { return cmdScope([]string{"-scope", empty}) })
	if exitCode(err) != exitError || !strings.Contains(err.Error(), "no in-scope web targets found") {
		t.Errorf("no in-scope web target: exit %d (%v), want 1", exitCode(err), err)
	}
	if _, _, err := captureBoth(t, func() error { return cmdScope(nil) }); exitCode(err) != exitUsage {
		t.Errorf("no -scope: exit %d, want 2", exitCode(err))
	}
	if _, _, err := captureBoth(t, func() error { return cmdScope([]string{"-scope", "hackerone"}) }); exitCode(err) != exitUsage {
		t.Errorf("a platform and no -program: exit %d, want 2", exitCode(err))
	}
}
