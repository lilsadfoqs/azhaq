package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The default resolvers' addresses are denied, so a name that would go to
// them fails visibly and nothing leaves the machine.
var denyDefaultResolvers = []string{
	"-deny", "1.1.1.1", "-deny", "1.0.0.1", "-deny", "8.8.8.8", "-deny", "8.8.4.4", "-deny", "9.9.9.9", "-deny", "149.112.112.112",
}

// dnsTargets are the resolvers the ledger shows for each name asked.
func dnsTargets(t *testing.T, path string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		var e struct{ Kind, Target, Host string }
		if json.Unmarshal([]byte(l), &e) == nil && e.Kind == "dns" {
			out[e.Host] = append(out[e.Host], e.Target)
		}
	}
	return out
}

// Without -resolvers a name in a zone the root zone does not delegate, or
// under home.arpa, is kept off the default resolvers and asked of the
// system's resolver (a stub): its answers are the rows, and the summary says
// how many it answered. A name in a delegated TLD is sent to the defaults as
// before (here they are denied).
func TestDNSAsksTheSystemResolverForNamesInUndelegatedZones(t *testing.T) {
	t.Chdir(t.TempDir())
	sys := newPTRStub(t)
	sys.answer(map[string]string{"app.corp.internal": "10.1.2.3", "printer.home.arpa": "192.168.1.9", "nas.lan": "10.0.0.7"})
	sys.asSystem(t)
	led := t.TempDir() + "/l.ledger"
	args := append([]string{"-d", "app.corp.internal,printer.home.arpa,nas.lan,dc01.corp,app.example.com", "-json", "-timeout", "300ms", "-ledger", led}, denyDefaultResolvers...)
	ls, rep, _ := dnsOut(t, args...)
	rows := dnsRows(t, ls)
	for h, ip := range sys.a {
		if a, _ := rows[h]["a"].([]any); len(a) != 1 || a[0] != ip {
			t.Errorf("%s: row %v, want the system's answer %s", h, rows[h], ip)
		}
	}
	if len(rows) != 3 {
		t.Errorf("%d rows, want the 3 names the system's resolver answered", len(rows))
	}
	if rep.Counts["did not resolve"] != 2 {
		t.Errorf("counts %v: dc01.corp, which the system's resolver did not answer, and app.example.com, whose resolvers are denied", rep.Counts)
	}
	var note string
	for _, n := range rep.Notes {
		if strings.Contains(n, "no public resolver can answer") {
			note = n
		}
	}
	if !strings.HasPrefix(note, "4 names (") || !strings.Contains(note, "asked of the system's resolver instead: it answered 3;") || !strings.HasSuffix(note, "name your own resolvers with -resolvers to ask them instead") {
		t.Errorf("note %q in %v", note, rep.Notes)
	}
	targets := dnsTargets(t, led)
	for _, h := range []string{"app.corp.internal", "printer.home.arpa", "nas.lan", "dc01.corp"} {
		if got := targets[h]; len(got) == 0 {
			t.Errorf("%s: no ledger line", h)
		} else {
			for _, tg := range got {
				if tg != "system" {
					t.Errorf("%s was asked of %s, want only the system's resolver", h, tg)
				}
			}
		}
	}
	if got := targets["app.example.com"]; len(got) == 0 || got[0] == "system" {
		t.Errorf("a delegated name: %v", got)
	}
}

// -resolvers names resolvers: they are asked for every name, held zones too,
// and the system's resolver is not.
func TestDNSAsksNamedResolversForNamesInUndelegatedZones(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	sys := newPTRStub(t).asSystem(t)
	_, rep, _ := dnsOut(t, "-d", "a.internal,b.home.arpa,c.lan,d.corp", "-r", lab.addr, "-json", "-silent")
	if lab.asked.Load() < 4 {
		t.Errorf("the named resolver was asked %d times, want a question for each of the 4 names", lab.asked.Load())
	}
	if len(sys.asked()) != 0 {
		t.Errorf("the system's resolver was asked %q", sys.asked())
	}
	for _, n := range rep.Notes {
		if strings.Contains(n, "no public resolver can answer") {
			t.Errorf("a note about names kept off the defaults with -resolvers: %q", n)
		}
	}
}

// plan says that names in undelegated zones are kept off the default
// resolvers and asked of the system's, and drops that when -resolvers names
// them.
func TestPlanSaysUndelegatedZonesGoToTheSystemResolver(t *testing.T) {
	line := func(args ...string) string {
		t.Helper()
		out, errOut, code := cli(t, append([]string{"plan", "-domain", "example.com", "-allow", "example.com", "-sources", "none", "-ports", "9"}, args...)...)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		for _, l := range strings.Split(out+errOut, "\n") {
			if strings.HasPrefix(l, "sends: DNS queries to ") {
				return l
			}
		}
		t.Fatalf("no DNS line in the plan:\n%s", out+errOut)
		return ""
	}
	const held = "a name in a zone the root zone does not delegate (.internal, .lan, .corp) or under home.arpa is kept off the default resolvers and asked of the system's resolver instead"
	if l := line(); !strings.Contains(l, "the default public resolvers (1.1.1.1, ") || !strings.Contains(l, held) || !strings.Contains(l, "-resolvers names resolvers that are asked for them") {
		t.Errorf("default resolvers: %s", l)
	}
	if l := line("-resolvers", "127.0.0.1:5301"); !strings.Contains(l, "the resolvers given (127.0.0.1:5301)") || strings.Contains(l, "root zone") {
		t.Errorf("with -resolvers: %s", l)
	}
}

// A run over a name in an undelegated zone sends none of its guesses to the
// default resolvers (here denied, so nothing leaves): they go to the system's
// resolver (a stub that knows two), and the summary says how many it asked
// and answered.
func TestRunAsksTheSystemResolverForGuessedNamesInUndelegatedZones(t *testing.T) {
	t.Chdir(t.TempDir())
	sys := newPTRStub(t)
	sys.answer(map[string]string{"www.app.corp.internal": "127.0.0.2", "mail.app.corp.internal": "127.0.0.3"})
	sys.asSystem(t)
	led := t.TempDir() + "/l.ledger"
	args := append([]string{"run", "-domain", "app.corp.internal", "-allow", "app.corp.internal", "-sources", "none", "-no-paths", "-web-ports", "65534", "-dns-brute", writeList(t, "www", "mail", "nope"), "-json", "-timeout", "60s", "-ledger", led}, denyDefaultResolvers...)
	out, errOut, code := cli(t, args...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	rep := lastReport(t, out+errOut)
	found := false
	for _, n := range rep.Notes {
		found = found || (strings.Contains(n, ".app.corp.internal") && strings.Contains(n, "no public resolver can answer") && strings.Contains(n, "asked of the system's resolver instead: it answered 2;"))
	}
	if !found {
		t.Errorf("no note about the names asked of the system's resolver: %v", rep.Notes)
	}
	for h, tg := range dnsTargets(t, led) {
		for _, x := range tg {
			if x != "system" {
				t.Errorf("%s was asked of %s", h, x)
			}
		}
	}
}

// A domain in an undelegated zone is asked of no third-party source, and the
// plan counts none; a public domain is counted.
func TestPlanCountsNoThirdPartyQueriesForUndelegatedZones(t *testing.T) {
	total := func(domain string) string {
		t.Helper()
		out, errOut, code := cli(t, "plan", "-domain", domain, "-allow", domain, "-json")
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", domain, code, errOut)
		}
		for _, l := range strings.Split(out, "\n") {
			if i := strings.Index(l, `"source_queries_total":`); i >= 0 {
				return strings.SplitN(strings.TrimPrefix(l[i:], `"source_queries_total":`), ",", 2)[0]
			}
		}
		t.Fatalf("%s: no source_queries_total in\n%s", domain, out)
		return ""
	}
	for _, d := range []string{"corp.internal", "nas.lan", "printer.home.arpa"} {
		if n := total(d); n != "0" {
			t.Errorf("%s: source_queries_total %s, want 0", d, n)
		}
	}
	if n := total("example.com"); n == "0" {
		t.Error("example.com: no source is planned")
	}
}
