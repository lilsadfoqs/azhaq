package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planJSON(t *testing.T, args ...string) runPlan {
	t.Helper()
	out, _, err := captureBoth(t, func() error { return cmdPlan(append(args, "-json")) })
	if err != nil {
		t.Fatal(err)
	}
	var p runPlan
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return p
}

// A plan for domains counts the source queries it knows it would make and
// bounds the requests to the targets, which depend on what resolves: a
// cost per web service, and the cap that applies. It sends nothing.
func TestPlanRequests(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "providers.yaml")
	if err := os.WriteFile(keys, []byte("shodan:\n  - k1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	none := filepath.Join(dir, "none.yaml")
	if err := os.WriteFile(none, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := planJSON(t, "-domain", "example.com", "-domain", "example.org", "-providers", none, "-max-requests", "5000").Requests
	if r.Sources["azhaq-rdap"] != 2 || r.Sources["azhaq-urls"] != 10 || r.Sources["azhaq-subdomains"] != 28 || r.Total != 40 || r.Sources["azhaq-search"] != 0 {
		t.Errorf("source queries %+v", r)
	}
	if len(r.NotCounted) != 0 || !r.Found || r.MaxNames != 200000 {
		t.Errorf("what is not known before the run %+v", r)
	}
	if r.PerService != 53 || r.Cap != 5000 || r.CapBy != "-max-requests" {
		t.Errorf("bound on the requests to the targets %+v", r)
	}

	// A scan engine with a key is asked; a daily allowance below
	// -max-requests is the cap that applies.
	r = planJSON(t, "-domain", "example.com", "-providers", keys, "-max-requests", "5000", "-daily-requests", "300", "-no-favicon").Requests
	if r.Sources["azhaq-search"] != 1 || r.Total != 22 {
		t.Errorf("keyed engine %+v", r)
	}
	if r.Cap != 300 || !strings.HasPrefix(r.CapBy, "-daily-requests") || r.PerService != 52 {
		t.Errorf("daily cap %+v", r)
	}

	r = planJSON(t, "-domain", "example.com", "-providers", none, "-passive").Requests
	if !r.Passive || r.PerService != 0 || r.Total != 20 {
		t.Errorf("passive %+v", r)
	}

	// -probe asks the names and their front pages, nothing more.
	r = planJSON(t, "-domain", "example.com", "-providers", none, "-probe").Requests
	if r.Total != 0 || r.PerService != 2 {
		t.Errorf("-probe %+v", r)
	}

	// A URL's own host is resolved, not enumerated: no source is asked
	// about an address.
	r = planJSON(t, "-url", "http://127.0.0.1:3001/", "-providers", none).Requests
	if r.Total != 0 || len(r.NotCounted) != 0 || r.Found || r.Cap != 0 || r.CapBy != "" || r.PerService != 53 {
		t.Errorf("an address %+v", r)
	}

	out, _, err := captureBoth(t, func() error {
		return cmdPlan([]string{"-domain", "example.com", "-providers", none, "-max-requests", "5000"})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"source queries: 20 about the targets above (azhaq-rdap 1, azhaq-subdomains 14, azhaq-urls 5)",
		"requests to the targets: at most 5000 (-max-requests)",
		"about 53 per web service (its page, the favicon, 51 built-in paths)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// A plan with Chrome says it sends GET, HEAD and OPTIONS only, or, with
// -browser-writes, that pages send their writes; -browser-writes without
// a Chrome that renders is refused.
func TestPlanChromeWrites(t *testing.T) {
	has := func(sends []string, prefix string) bool {
		for _, s := range sends {
			if strings.HasPrefix(s, prefix) {
				return true
			}
		}
		return false
	}
	if s := planJSON(t, "-url", "http://127.0.0.1:3001/", "-browser").Sends; !has(s, "Chrome sends GET, HEAD and OPTIONS only") || has(s, "Chrome lets pages send") {
		t.Errorf("-browser: %q", s)
	}
	if s := planJSON(t, "-url", "http://127.0.0.1:3001/", "-browser", "-browser-writes").Sends; !has(s, "Chrome lets pages send their writes") {
		t.Errorf("-browser-writes: %q", s)
	}
	if s := planJSON(t, "-url", "http://127.0.0.1:3001/").Sends; has(s, "Chrome") {
		t.Errorf("no Chrome: %q", s)
	}
	_, _, err := captureBoth(t, func() error {
		return cmdPlan([]string{"-url", "http://127.0.0.1:3001/", "-browser-writes", "-json"})
	})
	var ue usageErr
	if !errors.As(err, &ue) {
		t.Errorf("-browser-writes alone: %v", err)
	}
}

// The sends of a plan are true of what it plans: GET requests first, never
// said to be "only" (a GET can change data), and a line for each port scan,
// UDP probe, POST body and sign-in that is planned.
func TestPlanSendsNameWhatIsPlanned(t *testing.T) {
	joined := func(args ...string) string {
		return strings.Join(planJSON(t, append([]string{"-url", "http://127.0.0.1:3001/"}, args...)...).Sends, "\n")
	}
	if s := joined(); !strings.HasPrefix(s, "GET requests to the targets") || strings.Contains(strings.SplitN(s, "\n", 2)[0], "only") {
		t.Errorf("a plain run: %s", s)
	}
	if s := joined(); strings.Contains(s, "deny-path") || strings.Contains(s, "look like") || !strings.Contains(s, "azhaq cannot know what a GET does on the server") {
		t.Errorf("a plain run holds back nothing by name:\n%s", s)
	}
	if s := joined("-deny-path", `^/admin/`, "-deny-path", `action=wipe`); !strings.Contains(s, "matches -deny-path ^/admin/") || !strings.Contains(s, "matches -deny-path action=wipe") {
		t.Errorf("-deny-path:\n%s", s)
	}
	s := joined("-ports", "top-100")
	for _, want := range []string{"TCP connects (full handshakes) to 100 ports of each address", "each open port is asked what it is", "one HEAD /"} {
		if !strings.Contains(s, want) {
			t.Errorf("-ports top-100 lacks %q:\n%s", want, s)
		}
	}
	if s := joined("-ports", "22,80", "-port-detect", "none"); !strings.Contains(s, "to 2 ports") || !strings.Contains(s, "closed at once") || strings.Contains(s, "HEAD /") {
		t.Errorf("-port-detect none:\n%s", s)
	}
	if s := joined("-ports", "none", "-ports-udp", "top"); !strings.Contains(s, "UDP datagrams to 25 ports") || strings.Contains(s, "TCP connects") {
		t.Errorf("-ports-udp:\n%s", s)
	}
	for flag, want := range map[string][]string{
		"-graphql":      {"-graphql"},
		"-submit-forms": {"-submit-forms"},
	} {
		if s := joined(flag); !strings.Contains(s, "POST requests") || !strings.Contains(s, want[0]) {
			t.Errorf("%s:\n%s", flag, s)
		}
	}
	if s := joined("-graphql"); !strings.Contains(s, "at most 2 per endpoint, and up to 96 more when it refuses introspection") || !strings.Contains(s, "GraphiQL page is not asked") {
		t.Errorf("-graphql says no number for the POSTs it sends:\n%s", s)
	}
	if s := joined("-params", "small", "-params-method", "JSON", "-params-writes"); !strings.Contains(s, "JSON requests whose body holds the parameter names") {
		t.Errorf("-params-method JSON:\n%s", s)
	}
	if s := joined("-params", "small"); !strings.HasPrefix(s, "GET requests to the targets") {
		t.Errorf("-params by GET:\n%s", s)
	}
	// A click is made whatever it says: no word keeps one back.
	s = joined("-browser", "-interact")
	if !strings.Contains(s, "every click is made, a log out link included") || !strings.Contains(s, "refused by their method") || strings.Contains(s, "none is made") {
		t.Errorf("-interact:\n%s", s)
	}
	if s := joined("-browser", "-interact", "-browser-writes"); strings.Contains(s, "refused by their method") {
		t.Errorf("-interact with -browser-writes refuses nothing:\n%s", s)
	}
	if s := joined("-login", "http://127.0.0.1:3001/login", "-login-user", "bob", "-login-pass", "x"); !strings.Contains(s, "Chrome signs in at http://127.0.0.1:3001/login as bob") {
		t.Errorf("-login:\n%s", s)
	}
	// -passive leaves the pages out, not the port scan.
	s = joined("-passive", "-ports", "top-100")
	if strings.Contains(s, "nothing to the targets") || !strings.Contains(s, "TCP connects") {
		t.Errorf("-passive -ports:\n%s", s)
	}
	if s := joined("-passive"); !strings.Contains(s, "nothing to the targets (-passive)") {
		t.Errorf("-passive:\n%s", s)
	}
	if r := planJSON(t, "-url", "http://127.0.0.1:3001/", "-passive", "-ports", "top-100").Requests; r.Passive {
		t.Errorf("-passive -ports says no request goes to the targets: %+v", r)
	}
}

// plan -axfr lists the zone transfers dns -axfr would try, and what the scope
// leaves out of them, without sending anything.
func TestPlanListsZoneTransfers(t *testing.T) {
	p := planJSON(t, "-domain", "lab.test", "-url", "https://app.lab.test/", "-allow", "lab.test", "-resolvers", "127.0.0.1:5302", "-sources", "none", "-axfr")
	if len(p.AXFR) != 2 || p.AXFR[0].Zone != "lab.test" || p.AXFR[1].Zone != "app.lab.test" {
		t.Fatalf("the transfers: %+v", p.AXFR)
	}
	x := p.AXFR[0]
	if !strings.Contains(x.Lookups, "NS of lab.test") || !strings.Contains(x.Transfer, "if the scope allows it") || len(x.Resolvers) != 1 || x.Resolvers[0] != "127.0.0.1:5302" {
		t.Errorf("a transfer: %+v", x)
	}
	if !strings.Contains(strings.Join(p.Sends, "\n"), "is not contacted: the summary names it, and adding the address to -allow allows the transfer") {
		t.Errorf("sends: %q", p.Sends)
	}
	// Without the flag the plan says nothing of transfers.
	if q := planJSON(t, "-domain", "lab.test", "-sources", "none"); len(q.AXFR) != 0 {
		t.Errorf("a transfer planned without -axfr: %+v", q.AXFR)
	}
}

// A seed a -deny-path rule keeps out is listed as skipped with the rule, as
// run lists it, and is neither a target nor in the requests estimate; the CLI
// and the MCP tool say the same.
func TestPlanSkipsASeedADenyPathRuleKeepsOut(t *testing.T) {
	check := func(p runPlan) {
		t.Helper()
		for _, tg := range p.Targets {
			if strings.Contains(tg.Key, "/logout") {
				t.Errorf("/logout is a target of the plan: %+v", p.Targets)
			}
		}
		if len(p.Skipped) != 1 || !strings.HasSuffix(p.Skipped[0].Target, "/logout") || p.Skipped[0].Reason != "-deny-path ^/logout" {
			t.Errorf("skipped: %+v", p.Skipped)
		}
		home := false
		for _, tg := range p.Targets {
			home = home || strings.HasSuffix(tg.Key, "/home") && len(tg.Collectors) > 0
		}
		if !home {
			t.Errorf("the seed no rule matches stays a target: %+v", p.Targets)
		}
	}
	args := []string{"-url", "http://127.0.0.1:18081/logout", "-url", "http://127.0.0.1:18081/home", "-deny-path", "^/logout", "-sources", "none", "-depth", "0"}
	check(planJSON(t, args...))

	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &mcpServer{exe: exe, dir: filepath.Join(dir, "ws"), lock: []string{"-allow", "127.0.0.1:18081", "-deny-path", "^/logout"}, locked: true, held: heldRun{Sources: "none"}}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	text, isErr := callText(t, s, "azhaq_plan", map[string]any{"targets": []any{"http://127.0.0.1:18081/logout", "http://127.0.0.1:18081/home"}, "depth": 0})
	if isErr {
		t.Fatalf("azhaq_plan: %s", text)
	}
	var got struct {
		Plan []runPlan `json:"plan"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil || len(got.Plan) != 1 {
		t.Fatalf("azhaq_plan answered %v: %s", err, text)
	}
	check(got.Plan[0])
}
