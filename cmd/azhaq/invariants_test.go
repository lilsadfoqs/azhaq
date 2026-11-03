package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/scopefile"
	"github.com/lilsadfoqs/azhaq/scope"
)

// The global invariants every run a test makes must keep, whatever the test
// is about. cli, runContract and the capture helpers call them, so a run
// that breaks one fails its test:
//
//	F  a summary that lists a failure exits 0 only for a run that did its job, and counts it
//	   in failures (never under -strict-exit); an exit 0 with failures says exit 0
//	R  the summary's requests are the ledger's lines to targets
//	S  every result row names a host and port inside the scope given
//	D  with -resolvers, no DNS line of the ledger names the system's resolver

// argValues are the values of the flags named, as written in args:
// "-x v", "--x v" and "-x=v".
func argValues(args []string, names ...string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, val, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		found := false
		for _, n := range names {
			found = found || name == n
		}
		if !found {
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				break
			}
			i++
			val = args[i]
		}
		out = append(out, val)
	}
	return out
}

// lastSummary is the last JSON summary of stderr, if there is one.
func lastSummary(stderr string) (report, bool) {
	var last report
	found := false
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"type":"summary"`) {
			continue
		}
		var r report
		if json.Unmarshal([]byte(line), &r) == nil {
			last, found = r, true
		}
	}
	return last, found
}

// failureListed names what a summary lists as failed, "" when nothing.
func failureListed(rep report) string {
	switch {
	case len(rep.Failed) > 0:
		f := rep.Failed[0]
		return fmt.Sprintf("failed: %s %s %s", f.Collector, f.Source, f.Error)
	case len(rep.Unreachable) > 0:
		return "unreachable: " + rep.Unreachable[0]
	case rep.Degraded:
		return "degraded"
	}
	return ""
}

// checkFailureRule is invariant F: exit 0 with a failure listed is a run that
// did its job (see exit.go), and its summary counts the failure; -strict-exit
// has no such run.
func checkFailureRule(t *testing.T, what string, rep report, code int) {
	t.Helper()
	if why := failureListed(rep); why != "" && code == exitOK {
		if strictExit {
			t.Errorf("F %s: the summary lists %s and -strict-exit gave exit 0", what, why)
		}
		if rep.Failures == 0 {
			t.Errorf("F %s: the summary lists %s and counts no failure", what, why)
		}
	}
	if code == exitOK && rep.Exit != exitOK {
		t.Errorf("F %s: exit 0 and the summary says exit %d", what, rep.Exit)
	}
}

// checkSummaryOf runs invariant F on the last summary of a command's
// stderr, for the tests that call captureBoth and do not know the args.
func checkSummaryOf(t *testing.T, stderr string, err error) {
	t.Helper()
	if rep, ok := lastSummary(stderr); ok && rep.Type == "summary" {
		checkFailureRule(t, rep.Command, rep, exitCode(err))
	}
}

// checkRun runs R, D and S on one command line's outcome; F is run by the
// capture helpers the line went through.
func checkRun(t *testing.T, args []string, stdout, stderr string, code int) {
	t.Helper()
	what := strings.Join(args, " ")
	rep, ok := lastSummary(stderr)
	if !ok {
		return
	}
	checkLedgerInvariants(t, what, args, rep)
	checkRowsInScope(t, what, args, stdout, rep.Command)
}

// ledgerOf is the ledger a run's args wrote: -ledger FILE, else the
// workspace's own; "" when it wrote none.
func ledgerOf(args []string) string {
	if v := argValues(args, "ledger"); len(v) > 0 {
		if v[len(v)-1] == "off" {
			return ""
		}
		return v[len(v)-1]
	}
	if v := argValues(args, "db"); len(v) > 0 {
		if p := v[len(v)-1] + ".ledger.jsonl"; fileExists(p) {
			return p
		}
	}
	return ""
}

// lastRunLines are the lines of the ledger's last run: those after the seal
// before the last, up to the last. A file whose end is not sealed has its
// unsealed lines as the last run.
func lastRunLines(path string) ([]ledger.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cur, prev []ledger.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var e ledger.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		if e.Kind == ledger.KindSeal {
			prev, cur = cur, nil
			continue
		}
		cur = append(cur, e)
	}
	if len(cur) == 0 {
		cur = prev
	}
	return cur, sc.Err()
}

// checkLedgerInvariants are R and D.
func checkLedgerInvariants(t *testing.T, what string, args []string, rep report) {
	t.Helper()
	path := ledgerOf(args)
	if path == "" {
		return
	}
	lines, err := lastRunLines(path)
	if err != nil {
		return
	}
	if rep.Requests == 0 && strings.Contains(strings.Join(rep.Notes, "\n"), "the run sent nothing") {
		// A run that sends nothing adds no seal: the lines before are an earlier run's.
		lines = nil
	}
	rules := scopeOf(args)
	targets := 0
	for _, e := range lines {
		if e.IsTarget() {
			targets++
			if rules != nil && !ledgerLineInScope(rules, e) {
				t.Errorf("S %s: the ledger has a line to %s %s, outside the scope", what, e.Kind, e.Target)
			}
		}
		if len(argValues(args, "resolvers")) > 0 && e.Kind == "dns" && e.Target == "system" {
			t.Errorf("D %s: the ledger has a DNS line to the system's resolver for %s", what, e.Host)
		}
	}
	if !ledgerCounted(t, rep.Command) {
		return
	}
	if int64(targets) != rep.Requests {
		t.Errorf("R %s: the summary counts %d requests, the ledger holds %d lines to targets", what, rep.Requests, targets)
	}
}

// ledgerLineInScope says a line to a target names a host and port the rules
// let through, by the name the run knew it under or by its address.
func ledgerLineInScope(rules *scope.Rules, e ledger.Entry) bool {
	switch e.Kind {
	case "http", "chrome":
		u, err := url.Parse(e.Target)
		return err != nil || u.Hostname() == "" || rules.AllowsAddr(u.Hostname(), scope.URLPort(u))
	case "tcp", "udp":
		host, port, err := net.SplitHostPort(e.Target)
		if err != nil {
			return true
		}
		return rules.AllowsAddr(host, port) || e.Host != "" && rules.AllowsAddr(e.Host, port)
	}
	return true
}

// ledgerCounted says the command's summary counts the requests of its run
// alone: roles and watch run several in one ledger, and the commands that
// read a workspace send nothing, whatever its ledger holds.
func ledgerCounted(t *testing.T, command string) bool {
	switch command {
	case "roles", "watch", "notify", "worker", "ledger", "mcp", "query", "export", "report", "diff", "gallery":
		return false
	}
	_, killed := killedBefore.Load(t.Name())
	return !killed
}

// killedBefore holds the tests that kill a run before the one they check: its
// unsealed lines sit in the same file, so the last run's lines cannot be told
// from them.
var killedBefore sync.Map

func ledgerHoldsAKilledRun(t *testing.T) { killedBefore.Store(t.Name(), true) }

// scopeOf is the scope rules of args, with -scope files read; nil when the
// run named none.
func scopeOf(args []string) *scope.Rules {
	if len(argValues(args, "allow", "scope")) == 0 {
		return nil
	}
	rules, err := runRules(args, func(spec, program string) (scopefile.Scope, error) { return loadScope(spec, program) })
	if err != nil || len(rules.Allow) == 0 {
		return nil
	}
	rules = rules.Compile()
	return &rules
}

// rowEndpoints are the hosts and ports a result row names as its own.
func rowEndpoints(row map[string]any) (out [][2]string) {
	if row["scope"] == "fanout" || row["type"] == "IPAddress" {
		return nil // found on the way, or what an in-scope name resolves to
	}
	if row["failed"] == true || row["error"] != nil {
		return nil // the refusal of a target the user named: it says what happened to it
	}
	str := func(k string) string { s, _ := row[k].(string); return s }
	add := func(host, port string) {
		if host != "" {
			out = append(out, [2]string{host, port})
		}
	}
	fromRaw := func(raw string) {
		if raw == "" {
			return
		}
		if strings.Contains(raw, "://") {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
				add(u.Hostname(), scope.URLPort(u))
			}
			return
		}
		if strings.ContainsAny(raw, " /?#") {
			return // a path, a pattern or a sentence
		}
		if h, p, ok := splitHostPort(raw); ok {
			add(h, p)
		}
	}
	for _, k := range []string{"url", "input", "key", "host", "target"} {
		fromRaw(str(k))
	}
	if ip := str("ip"); ip != "" {
		port := ""
		switch p := row["port"].(type) {
		case float64:
			port = strconv.Itoa(int(p))
		case string:
			port = p
		}
		add(ip, port)
	}
	if h := str("host"); h != "" {
		if p, ok := row["port"].(float64); ok {
			add(h, strconv.Itoa(int(p)))
		}
	}
	return out
}

// splitHostPort reads "host" or "host:port"; ok is false for anything that
// is not a name or an address.
func splitHostPort(s string) (host, port string, ok bool) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, h != ""
	}
	if strings.Contains(s, ":") && net.ParseIP(s) == nil {
		return "", "", false
	}
	return s, "", s != ""
}

// checkRowsInScope is S: with -allow or -scope, each JSON result row names
// only hosts and ports the rules let through.
func checkRowsInScope(t *testing.T, what string, args []string, stdout, command string) {
	t.Helper()
	if command == "query" || command == "export" || command == "diff" || command == "report" {
		return // they read a workspace, whose rows were found on the way too
	}
	rules := scopeOf(args)
	if rules == nil {
		return
	}
	for _, l := range lines(stdout) {
		var row map[string]any
		if !strings.HasPrefix(l, "{") || json.Unmarshal([]byte(l), &row) != nil {
			continue
		}
		for _, hp := range rowEndpoints(row) {
			if !rules.AllowsAddr(hp[0], hp[1]) {
				t.Errorf("S %s: a row names %s:%s, outside the scope: %s", what, hp[0], hp[1], l)
			}
		}
	}
}

// The helpers read what they should: a failure of any kind is listed, a
// row's own host and port are found and a found-on-the-way row is not, and
// the ledger's last run is the lines after the seal before the last.
func TestInvariantHelpers(t *testing.T) {
	for _, c := range []struct {
		rep  report
		want bool
	}{
		{report{}, false},
		{report{Failed: []engine.Failure{{Collector: "c", Partial: true}}}, true},
		{report{Failed: []engine.Failure{{Collector: "c", Fanout: true}}}, true},
		{report{Unreachable: []string{"h"}}, true},
		{report{Degraded: true}, true},
	} {
		if got := failureListed(c.rep) != ""; got != c.want {
			t.Errorf("%+v: failure listed %v, want %v", c.rep, got, c.want)
		}
	}
	if got := argValues([]string{"run", "-allow", "a", "--allow=b", "-json", "-ledger", "x"}, "allow"); strings.Join(got, ",") != "a,b" {
		t.Errorf("argValues %v", got)
	}
	var own, found [][2]string
	own = rowEndpoints(map[string]any{"url": "http://h.test:8080/p", "host": "h.test"})
	found = rowEndpoints(map[string]any{"url": "http://other.test/", "scope": "fanout"})
	if len(own) != 2 || own[0] != [2]string{"h.test", "8080"} || len(found) != 0 {
		t.Errorf("own %v, found on the way %v", own, found)
	}
	rules := scope.Rules{Allow: []string{"127.0.0.1:80"}}.Compile()
	if !ledgerLineInScope(&rules, ledger.Entry{Kind: "tcp", Target: "127.0.0.1:80"}) || ledgerLineInScope(&rules, ledger.Entry{Kind: "http", Target: "http://127.0.0.1:81/"}) {
		t.Error("ledgerLineInScope does not hold the port")
	}
	path := filepath.Join(t.TempDir(), "l.jsonl")
	l, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{2, 3} {
		for range n {
			l.Record(ledger.Entry{Kind: "http", Target: "http://127.0.0.1/"})
		}
		l.Record(ledger.Entry{Kind: ledger.KindSeal})
	}
	_ = l.Close()
	if got, err := lastRunLines(path); err != nil || len(got) != 3 {
		t.Errorf("last run has %d lines (%v), want 3", len(got), err)
	}
}
