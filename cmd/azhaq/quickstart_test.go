package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// A target is a URL with its scheme, an address or a name with a dot; any
// other word is still an unknown command, with its suggestion.
func TestAWordThatIsATargetStartsTheGuidedRun(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("scope.csv", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ arg, kind, value string }{
		{"https://app.example.com/", "-url", "https://app.example.com/"},
		{"http://127.0.0.1:3000/", "-url", "http://127.0.0.1:3000/"},
		{"example.com", "-domain", "example.com"},
		{"Example.COM", "-domain", "example.com"},
		{"192.0.2.7", "-cidr", "192.0.2.7/32"},
	} {
		if kind, value, ok := guidedTarget(c.arg); !ok || kind != c.kind || value != c.value {
			t.Errorf("%s: %q %q %v, want %s %s", c.arg, kind, value, ok, c.kind, c.value)
		}
	}
	for _, arg := range []string{"", "-json", "runn", "subz", "scope.csv", "example.com:8080", "example.com/path", "ftp://example.com/", "http://", "a b.com"} {
		if _, _, ok := guidedTarget(arg); ok {
			t.Errorf("%q is taken for a target", arg)
		}
	}
	_, errOut, code := cli(t, "runn")
	if code != exitUsage || !strings.Contains(errOut, "unknown command") || !strings.Contains(errOut, "did you mean") {
		t.Errorf("a typo of a command: exit %d\n%s", code, errOut)
	}
}

// azhaq URL is azhaq run -url URL: the same rows, with the plan and its cost
// first, and the commands to go deeper last.
func TestGuidedRunMakesTheSameMapAsTheExplicitRun(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	dir := t.TempDir()
	rows := func(s string) string {
		lines := strings.Split(strings.TrimSpace(s), "\n")
		sort.Strings(lines)
		return strings.Join(lines, "\n")
	}
	want, _, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", filepath.Join(dir, "run.db"))
	if code != exitOK {
		t.Fatalf("run: exit %d", code)
	}
	got, errOut, code := cli(t, srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", filepath.Join(dir, "guided.db"))
	if code != exitOK {
		t.Fatalf("guided: exit %d\n%s", code, errOut)
	}
	if rows(got) != rows(want) {
		t.Errorf("the guided map is not the explicit run's:\n--- guided\n%s\n--- run\n%s", got, want)
	}
	plan := strings.Index(errOut, "estimate: at least 26 requests")
	summary := strings.Index(errOut, "azhaq run: ")
	hunt := strings.Index(errOut, "next: azhaq hunt -db "+filepath.Join(dir, "guided.db"))
	if plan < 0 || summary < 0 || hunt < 0 || !(plan < summary && summary < hunt) {
		t.Errorf("the plan and its estimate (%d), the map's summary (%d) and the commands to go deeper (%d) are not in that order:\n%s", plan, summary, hunt, errOut)
	}
	if !strings.Contains(errOut, "-dirs @common -db") || !strings.Contains(errOut, "(next pass, not run: ") {
		t.Errorf("the summary does not say the wider passes it did not make:\n%s", errOut)
	}
}

// -quiet and -json leave stderr to the summary, as for run; quickstart is the
// same command as the bare target.
func TestQuickstartKeepsRunsOutputContracts(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	_, errOut, code := cli(t, "quickstart", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-json", "-db", filepath.Join(t.TempDir(), "q.db"))
	sum := sumMap(t, errOut)
	if code != exitOK || sum["command"] != "run" || strings.Contains(errOut, "estimate:") {
		t.Errorf("exit %d, command %v:\n%s", code, sum["command"], errOut)
	}
	var next []string
	for _, n := range sum["next"].([]any) {
		next = append(next, n.(string))
	}
	if !strings.Contains(strings.Join(next, "\n"), "azhaq hunt -db ") {
		t.Errorf("the summary's next has no way to go deeper: %v", next)
	}
	if _, errOut, code = cli(t, "quickstart"); code != exitUsage || !strings.Contains(errOut, "give the one target") {
		t.Errorf("quickstart with no target: exit %d\n%s", code, errOut)
	}
}

// help groups the commands by task, and opens with the way to start.
func TestHelpGroupsTheCommandsByTask(t *testing.T) {
	out, _, _ := cli(t, "help")
	order := []string{"Start here:", "Map a target:", "Find one thing", "Read and compare results:", "Other:"}
	at := -1
	for _, g := range order {
		i := strings.Index(out, "\n"+g)
		if i < 0 || i < at {
			t.Fatalf("the group %q is missing or out of order:\n%s", g, out)
		}
		at = i
	}
	if !strings.Contains(out, "azhaq TARGET") || !strings.Contains(out, "quickstart") {
		t.Errorf("help does not open with the guided first map:\n%s", out)
	}
	// Every command is in one group, and every group is listed.
	seen := map[string]int{}
	for _, c := range commands {
		seen[c.group]++
		found := false
		for _, g := range groups {
			found = found || g == c.group
		}
		if !found {
			t.Errorf("%s is in the group %q that help does not list", c.name, c.group)
		}
	}
}

// A scan of the top ports names the range it did not ask, what asking it
// would send, and the command, for a run and for ports; a scan of every port
// names none.
func TestATopPortsScanNamesTheUnaskedRange(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	port := portOfURL(srv.URL)
	sum := runJSON(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", filepath.Join(t.TempDir(), "w.db"), "-ports", "top-1000,"+port, "-port-detect", "none", "-no-paths")
	var pass string
	for _, n := range sum["next"].([]any) {
		if s := n.(string); strings.Contains(s, "next pass, not run: the other ") {
			pass = s
		}
	}
	if !strings.Contains(pass, "azhaq ports -host 127.0.0.1 -p full -db ") || !strings.Contains(pass, "64535 connects") && !strings.Contains(pass, "64534 connects") {
		t.Errorf("the run's next has no wider port pass with its cost: %v", sum["next"])
	}
	if !strings.Contains(pass, " TCP ports were not asked on 1 address") || !strings.Contains(pass, "open port") {
		t.Errorf("the wider pass does not say what was not asked: %s", pass)
	}

	// ports says it with the targets and flags it was given, minus the ports.
	_, errOut, _ := cli(t, "ports", "-host", "127.0.0.1", "-p", "top-100,"+port, "-json")
	sum = sumMap(t, errOut)
	next, _ := json.Marshal(sum["next"])
	if !strings.Contains(string(next), "azhaq ports -host 127.0.0.1 -json -p full") || !strings.Contains(string(next), "65434 connects") && !strings.Contains(string(next), "65435 connects") {
		t.Errorf("ports names no wider pass: %s", next)
	}

	// Every port asked: nothing left to suggest; a pass the user did not ask for is a line, never a request.
	if why, cost := portsPass(allTCPPorts, 3, 5); why != "" || !cost.zero() {
		t.Errorf("a scan of every port suggests %q (%v)", why, cost)
	}
	if why, cost := portsPass(1000, 2, 0); cost.Connects != 2*64535 || !strings.Contains(why, "no open port was found") {
		t.Errorf("1000 ports on 2 addresses: %q, %v", why, cost)
	}
}

// subs without -live lists names no lookup checked: the next pass is -live,
// at about two DNS queries a name; roles that replayed no write says what the
// histories' writes would send.
func TestOtherNextPassesCountWhatTheyWouldSend(t *testing.T) {
	if why, cost := livePass(300); cost.DNS != 600 || !strings.Contains(why, "300 names listed by the sources were not looked up") {
		t.Errorf("live pass: %q %v", why, cost)
	}
	if why, _ := livePass(0); why != "" {
		t.Errorf("no names: %q", why)
	}
	if got := livePassCommand([]string{"-d", "example.com", "-json"}); got != "azhaq subs -d example.com -json -live" {
		t.Errorf("live command %q", got)
	}

	var hits atomic.Int64
	srv := vampiShaped(&hits)
	defer srv.Close()
	alice := writeHAR(t, "alice.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/books/v1", "", 200, "Authorization", "Bearer t-alice"),
		harEntry("2026-10-29T10:00:01.000Z", "POST", srv.URL+"/books/v1", `{"book_title":"x"}`, 200, "Authorization", "Bearer t-alice", "Content-Type", "application/json"))
	bob := writeHAR(t, "bob.har", harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/books/v1", "", 200, "Authorization", "Bearer t-bob"))
	flags := []string{"roles", "-har", "alice=" + alice, "-har", "bob=" + bob, "-json", "-dir", t.TempDir()}
	_, errOut, _ := cli(t, flags...)
	next, _ := json.Marshal(sumMap(t, errOut)["next"])
	if !strings.Contains(string(next), "-replay-writes post,put,patch") || !strings.Contains(string(next), "1 write in the histories were not replayed") || !strings.Contains(string(next), "changes data on the target") {
		t.Errorf("roles names no pass for the history's write: %s", next)
	}
	asked := hits.Load()
	_, errOut, _ = cli(t, append(flags[:len(flags)-2:len(flags)-2], "-replay-writes", "post", "-dir", t.TempDir())...)
	if next, _ := json.Marshal(sumMap(t, errOut)["next"]); strings.Contains(string(next), "-replay-writes post,put,patch") {
		t.Errorf("a run that replayed the writes suggests replaying them: %s", next)
	}
	_ = asked
}

// A scope larger than the targets says what -sweep would send for the rest of
// it: a connect for each port asked of each address, else a request each.
func TestSweepLeadCountsWhatSweepWouldSend(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := newSweepLab(t)
	_, errOut, _ := cli(t, "ports", "-host", "127.7.7.2", "-p", lab.port, "-json", "-allow", "127.7.7.0/29")
	if n := notesOf(sumMap(t, errOut)); !strings.Contains(n, "-sweep covers the other 7, within -deny, -rate and -max-requests; it would send about 7 connects (1 port asked of each)") {
		t.Errorf("the lead does not count what -sweep would send: %s", n)
	}
	if got := sweepLead([]string{"127.7.7.0/29"}, nil, namedAddrs(nil), 0); got != "" {
		t.Errorf("no target names an address of the range: %q", got)
	}
}
