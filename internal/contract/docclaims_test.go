package contract

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The documentation promises behaviours: "sends nothing", "records every
// request", "every kept name is stored". Each promise listed here is a
// phrase of a page and a proof: a check that runs the binary and sees the
// promise kept, or the test of this package that does. A phrase that is gone
// from its page fails the test, so a reworded promise carries its proof with
// it. TestPromisesWithoutAProof lists the promises of the pages that no
// entry covers.

type claim struct {
	id string
	// on are the phrases of the pages that make the promise, each as "file: phrase" with
	// the file from the module's root.
	on    []string
	known string
	// test names the test of this package that proves it, or check proves it here.
	test  string
	check func(v *Inv, l *Labs)
}

func claims() []claim {
	nothingReached := func(v *Inv, l *Labs, what string) {
		if n := l.Site.Wire.Total() + l.Proxy.Wire.Total(); n != 0 {
			v.Errorf("%s: %d requests reached the site", what, n)
		}
	}
	return []claim{
		{id: "plan sends nothing", on: pages("README.md", "what a run would send; sends nothing", "README.md", "what it would ask, sends nothing"), check: func(v *Inv, l *Labs) {
			r := l.Cmd("plan", "-url", l.Site.URL, "-allow", l.Allow(), "-ledger", "l.jsonl")
			nothingReached(v, l, "plan")
			v.Equal("plan: requests in the summary", r.Summary.Requests, 0)
			if _, err := os.Stat(filepath.Join(l.Dir, "l.jsonl")); err == nil && len(ledgerSent(readLedger(l.T, filepath.Join(l.Dir, "l.jsonl"))).HTTP) > 0 {
				v.Errorf("plan wrote requests to a ledger")
			}
		}},
		{id: "hunt sends nothing", on: pages("docs/commands/hunt.md", "It sends nothing."), test: "TestCommandsThatReadSendNothing"},
		{id: "report sends nothing", on: pages("docs/commands/report.md", "sends nothing"), test: "TestCommandsThatReadSendNothing"},
		{id: "mcp status sends nothing", on: pages("docs/MCP.md", "Sends nothing and starts no command."), check: func(v *Inv, l *Labs) {
			c := startMCP(l.T, l.Dir, "-allow", l.Allow())
			c.Tool("azhaq_status", map[string]any{})
			nothingReached(v, l, "azhaq_status")
		}},
		{id: "-passive sends nothing to the targets", on: pages("README.md", "`-passive` sends nothing to the targets", "docs/CONCEPTS.md", "`-passive` sends nothing to the targets"), check: func(v *Inv, l *Labs) {
			r := l.Cmd("run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-passive", "-db", "w.db", "-proxy", l.Proxy.URL)
			nothingReached(v, l, "run -passive")
			v.Equal("run -passive: requests in the summary", r.Summary.Requests, 0)
		}},
		{id: "no request outside the scope", on: pages("docs/CONCEPTS.md", "No request to a target goes outside it, and Chrome's requests are included.", "README.md", "No request to a target goes to a host outside the", "docs/CONCEPTS.md", "No request to a target goes to a host outside the"), check: func(v *Inv, l *Labs) {
			l.Other = newSite(l.T)
			l.Site.SetEmbed(l.Other.URL + "/x")
			l.Cmd("run", "-url", l.Site.URL+"/embed", "-allow", l.Allow(), "-sources", "none", "-db", "w.db")
			l.Cmd("crawl", "-u", l.Site.URL+"/embed", "-d", "3", "-allow", l.Allow())
			if n := l.Other.Wire.Total(); n != 0 {
				v.Errorf("%d requests reached a host outside the scope", n)
			}
		}},
		{id: "without a scope requests stay on the site", on: pages("docs/CONCEPTS.md", "Without a scope, requests stay on the site.", "README.md", "Without a scope, requests stay on the site."), check: func(v *Inv, l *Labs) {
			// Another name for this machine is another site; another port of one name is not.
			l.Other = newSite(l.T)
			l.Site.SetEmbed(strings.Replace(l.Other.URL, "127.0.0.1", "localhost", 1) + "/x")
			l.Cmd("run", "-url", l.Site.URL+"/embed", "-sources", "none", "-db", "w.db")
			l.Cmd("crawl", "-u", l.Site.URL+"/embed", "-d", "3")
			if n := l.Other.Wire.Total(); n != 0 {
				v.Errorf("%d requests reached another site with no scope given", n)
			}
		}},
		{id: "a redirect to another site is not requested", on: pages("docs/MIGRATING.md", "A redirect to another site is recorded and not requested, even with `-fr`."), check: func(v *Inv, l *Labs) {
			l.Other = newSite(l.T)
			l.Site.SetRedirect("/away", l.Other.URL+"/landing")
			l.Cmd("probe", "-u", l.Site.URL, "-path", "/away", "-fr", "-allow", l.Allow())
			if n := l.Other.Wire.Total(); n != 0 {
				v.Errorf("probe -fr followed a redirect to another site: %d requests", n)
			}
		}},
		{id: "the kill file stops every request", on: pages("README.md", "no request, connection or query starts after it exists"), test: "TestExitCodeFollowsTheOutcome"},
		{id: "every kept name is stored", on: pages("docs/commands/subs.md", "Every name a source gave and a run kept is stored"), check: func(v *Inv, l *Labs) {
			l.Resolver = newResolver(l.T, "lab.test", "www", "api", "mail")
			w := l.File("words.txt", "www\napi\nmail\nnope\n")
			r := l.Cmd("subs", "-d", "lab.test", "-sources", "none", "-w", w, "-live", "-resolvers", l.Resolver.Addr, "-no-history", "-db", "w.db")
			q := RunRaw(l.T, l.Dir, nil, "query", "-db", "w.db", "-type", "Hostname", "-json")
			v.Equal("subs: names printed, against the Hostname rows of the workspace", int64(r.Summary.Results), int64(q.Summary.Results))
		}},
		{id: "-max-requests counts every request, calibration included", on: pages("docs/MIGRATING.md", "Every request, calibration included, counts against `-max-requests`"), check: func(v *Inv, l *Labs) {
			w := l.File("w.txt", "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n")
			r := RunRaw(l.T, l.Dir, nil, "dirs", "-u", l.Site.URL, "-w", w, "-max-requests", "7", "-proxy", l.Proxy.URL, "-json")
			if got := l.Proxy.Wire.Total(); got > 7 {
				v.Errorf("dirs -max-requests 7: %d requests reached the site", got)
			}
			v.Equal("dirs -max-requests 7: the summary's requests, against the wire", r.Summary.Requests, int64(l.Proxy.Wire.Total()))
		}},
		{id: "every request goes in the ledger", on: pages("docs/CONCEPTS.md", "Every request, connection and query goes in the", "README.md", "Every request and connection of a run with a workspace is recorded", "README.md", "scope, budget and ledger on every request"), test: "TestWireIsLedgerIsSummary"},
		{id: "the proxy sees each request", on: pages("docs/CONCEPTS.md", "The proxy sees each one, and the ledger counts the same."), test: "TestWireIsLedgerIsSummary"},
		{id: "ledger lines equal the proxy's count", on: pages("docs/OUTPUT.md", "equal the requests a proxy in front of them counts"), test: "TestWireIsLedgerIsSummary"},
		{id: "a GET unless a flag says write", on: pages("docs/CONCEPTS.md", "Without a flag, every request azhaq sends to a target on purpose is a GET", "README.md", "Without a flag, every request azhaq sends to a target on purpose is a GET"), test: "TestWireIsLedgerIsSummary"},
		{id: "a -deny-path rule keeps a path out", on: pages("docs/CONCEPTS.md", "`-deny-path REGEX` keeps a path out of every request"), test: "TestExitCodeFollowsTheOutcome"},
		{id: "roles requests are the ledger's lines", on: pages("docs/commands/roles.md", "It equals the target lines of `roles.ledger.jsonl`"), test: "TestWireIsLedgerIsSummary"},
		{id: "Chrome off-scope assets are marked, exit 0", on: pages("docs/commands/shots.md", "The run still exits 0, because the scope is yours."), test: "TestExitCodeFollowsTheOutcome"},
	}
}

// pages is one phrase of one page, and more as file, phrase pairs.
func pages(pairs ...string) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, pairs[i]+": "+pairs[i+1])
	}
	return out
}

func readFile(t testing.TB, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(moduleRoot(), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// testsOfThisPackage are the names of the tests the package's files declare.
func testsOfThisPackage(t testing.TB) map[string]bool {
	t.Helper()
	files, _ := filepath.Glob("*_test.go")
	re := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	out := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		must(t, err)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
	}
	return out
}

func TestDocumentedPromisesAreKept(t *testing.T) {
	have := testsOfThisPackage(t)
	for _, c := range claims() {
		t.Run(c.id, func(t *testing.T) {
			for _, p := range c.on {
				file, text, _ := strings.Cut(p, ": ")
				if !strings.Contains(readFile(t, file), text) {
					t.Fatalf("%s no longer says %q: reword the promise here with its page, with its proof", file, text)
				}
			}
			if c.test != "" {
				if !have[c.test] {
					t.Fatalf("its proof %s is not a test of this package", c.test)
				}
				return
			}
			l := newLabs(t)
			v := newInv(t, c.known)
			c.check(v, l)
			v.Done()
		})
	}
}

// promise is what makes a line of a page read as a promise about what azhaq
// sends or keeps.
var promise = regexp.MustCompile(`(?i)\b(sends? nothing|sent nothing|nothing is sent|sends no\b|records every|every request|no request|every kept|never sends|never requests|is never sent|stays? on the site)`)

// TestPromisesWithoutAProof lists the promises of README.md and docs/ that no
// entry above covers, so the list shrinks when one gets a proof. It fails on
// none: AZHAQ_CONTRACT_UNCOVERED=FILE writes the list there.
func TestPromisesWithoutAProof(t *testing.T) {
	covered := claims()
	var lines []string
	root := moduleRoot()
	for _, dir := range []string{"README.md", "docs"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") || filepath.Base(p) == "ARCHITECTURE.md" {
				return nil // ARCHITECTURE.md is how the code works, not what a user is promised
			}
			rel, _ := filepath.Rel(root, p)
			b, _ := os.ReadFile(p)
			inFlags := false
			for i, line := range strings.Split(string(b), "\n") {
				switch {
				case strings.Contains(line, "<!-- flags:begin"):
					inFlags = true
				case strings.Contains(line, "<!-- flags:end"):
					inFlags = false
				}
				if inFlags || strings.HasPrefix(line, "| `-") || !promise.MatchString(line) {
					continue
				}
				proved := false
				for _, c := range covered {
					for _, p := range c.on {
						file, text, _ := strings.Cut(p, ": ")
						proved = proved || file == rel && strings.Contains(line, text)
					}
				}
				if !proved {
					lines = append(lines, fmt.Sprintf("%s:%d: ", rel, i+1)+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	sort.Strings(lines)
	t.Logf("%d promises of the documentation have no proof here yet", len(lines))
	if out := os.Getenv("AZHAQ_CONTRACT_UNCOVERED"); out != "" {
		must(t, os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	}
}
