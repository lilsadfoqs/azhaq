package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// askedOf is the names a ledger says a run asked in DNS.
func askedOf(t *testing.T, path string) map[string]bool {
	t.Helper()
	asked := map[string]bool{}
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Class == ledger.ClassDNS {
			asked[e.Host] = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return asked
}

// subs takes -allow, -deny and -scope as dns does: a name held out by them gets
// no DNS query, under -live, -w and -permute, and is counted as held out by scope.
func TestSubsDenyKeepsANameOutOfEveryQuery(t *testing.T) {
	words := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(words, []byte("secret\nadmin\nshop\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zone := fakeZone{a: map[string]string{"www.example.org": "192.0.2.1", "api.example.org": "192.0.2.2", "admin.example.org": "192.0.2.3", "secret.example.org": "192.0.2.4", "api-dev.example.org": "192.0.2.5", "shop.example.org": "192.0.2.6"}}
	for _, tc := range []struct {
		name string
		args []string
		deny []string
	}{
		{"live", []string{"-live"}, []string{"admin.example.org"}},
		{"words", []string{"-w", words}, []string{"secret.example.org"}},
		{"permute", []string{"-permute"}, []string{"api-dev.example.org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			resolvers := serveZone(t, zone)
			defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "api.example.org", "admin.example.org"}})()
			args := append([]string{"subs", "-d", "example.org", "-resolvers", resolvers, "-no-history", "-ledger", "l.jsonl", "-dns-rate", "0"}, tc.args...)
			for _, d := range tc.deny {
				args = append(args, "-deny", d)
			}
			out, rep, code := runContract(t, args...)
			if code != exitOK {
				t.Fatalf("exit %d: %s %v", code, rep.Error, rep.Notes)
			}
			asked := askedOf(t, "l.jsonl")
			if len(asked) == 0 {
				t.Fatalf("no DNS line in the ledger: the test asks nothing")
			}
			for _, d := range tc.deny {
				if asked[d] {
					t.Errorf("%s is denied and has a ledger line", d)
				}
				if strings.Contains(out, `"host":"`+d+`"`) {
					t.Errorf("%s is denied and is listed:\n%s", d, out)
				}
			}
			if !asked["www.example.org"] && tc.name == "live" {
				t.Errorf("www.example.org was not asked")
			}
		})
	}
}

// A name a source gave that the scope holds out is counted, and the counts add up.
func TestSubsCountsTheNamesHeldOutByScope(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.1", "api.example.org": "192.0.2.2"}})
	defer subcol.UseTestSources(subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org", "api.example.org", "admin.example.org", "x.admin.example.org"}})()
	for _, extra := range [][]string{{"-live"}, {}} {
		args := append([]string{"subs", "-d", "example.org", "-resolvers", resolvers, "-no-history", "-deny", "admin.example.org"}, extra...)
		out, rep, code := runContract(t, args...)
		if code != exitOK {
			t.Fatalf("%v: exit %d: %s %v", extra, code, rep.Error, rep.Notes)
		}
		if rep.Counts["held out by scope"] != 2 {
			t.Errorf("%v: counts %v: want admin.example.org and x.admin.example.org held out by scope", extra, rep.Counts)
		}
		if strings.Contains(out, "admin.example.org\"") && !strings.Contains(out, "x.admin") {
			t.Errorf("%v: admin.example.org is listed:\n%s", extra, out)
		}
		if got := namesFromCounts(rep.Counts); got != rep.Results {
			t.Errorf("%v: the counts give %d names, %d printed: %v", extra, got, rep.Results, rep.Counts)
		}
	}
}

// A name only subdomain.center guessed is held out like any other: it is not
// looked up, and the summary counts it as held out by scope, not as one that did
// not resolve.
func TestSubsDenyKeepsAGuessOutOfTheCheck(t *testing.T) {
	t.Chdir(t.TempDir())
	resolvers := serveZone(t, fakeZone{a: map[string]string{"www.example.org": "192.0.2.1", "guess1.example.org": "192.0.2.2", "guess2.example.org": "192.0.2.3"}})
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "s", Default: true, Names: []string{"www.example.org"}},
		subcol.TestSource{Name: "pad", Default: true, Padding: true, Sampled: true, Names: []string{"guess1.example.org", "guess2.example.org", "guess3.example.org"}},
	)()
	out, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolvers, "-no-history", "-ledger", "l.jsonl", "-dns-rate", "0", "-deny", "guess2.example.org")
	if code != exitOK {
		t.Fatalf("exit %d: %s %v", code, rep.Error, rep.Notes)
	}
	asked := askedOf(t, "l.jsonl")
	if asked["guess2.example.org"] || !asked["guess1.example.org"] {
		t.Errorf("asked %v: want guess1 asked and guess2 (denied) not", asked)
	}
	if strings.Contains(out, "guess2") || !strings.Contains(out, "guess1.example.org") {
		t.Errorf("rows:\n%s", out)
	}
	if rep.Counts["held out by scope"] != 1 || rep.Counts["did not resolve"] != 1 {
		t.Errorf("counts %v: want guess2 held out by scope and guess3 not resolving", rep.Counts)
	}
	if got := namesFromCounts(rep.Counts); got != rep.Results {
		t.Errorf("the counts give %d names, %d printed: %v", got, rep.Results, rep.Counts)
	}
}
