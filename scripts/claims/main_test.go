package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree writes a small repository: a README, one command page, a bench check,
// a test, and the ledger.
func tree(t *testing.T, readme, page, ledger string) string {
	t.Helper()
	root := t.TempDir()
	put := func(name, text string) {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("README.md", readme)
	put("docs/commands/run.md", page)
	put("docs/claims.tsv", ledger)
	put("cmd/azhaq/a_test.go", "package main\n\nfunc TestKeepsScope(t *testing.T) {}\n")
	put("bench/scope.go", "package main\n\nfunc f() { addCheck(\"scope: nothing leaves the scope\", true, \"\") }\n")
	return root
}

const page = "# azhaq run\n\n## What it does\n\n1. Never sends a write without its flag.\n2. Prints a map.\n\n## Flags\n\nNever edited by hand.\n"

func problems(t *testing.T, readme, page, ledger string) string {
	t.Helper()
	rep, err := check(tree(t, readme, page, ledger))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(rep.Problems, "\n")
}

func TestAClaimWithAProofPasses(t *testing.T) {
	ledger := "@cover docs/commands/run.md\nrun.no-writes\tdocs/commands/run.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope;bench:scope: nothing leaves\n"
	if got := problems(t, "# azhaq\n", page, ledger); got != "" {
		t.Errorf("problems: %s", got)
	}
}

func TestACoveredPageClaimWithNoProofFails(t *testing.T) {
	got := problems(t, "# azhaq\n", page, "@cover docs/commands/run.md\n")
	if !strings.Contains(got, "run.md:5: a claim with no proof") || strings.Contains(got, "run.md:9") {
		t.Errorf("want the claim of line 5 and not the Flags section:\n%s", got)
	}
}

func TestAPageNotCoveredIsListedNotFailed(t *testing.T) {
	root := tree(t, "# azhaq\n", page, "")
	if err := os.WriteFile(filepath.Join(root, "docs", "CONCEPTS.md"), []byte("# Concepts\n\n## Scope\n\nNo request goes outside it.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := check(root)
	if err != nil || rep.Backlog["docs/CONCEPTS.md"] != 1 {
		t.Errorf("%v %+v", err, rep)
	}
	// -list prints the sentences of a page that have no claim, covered or not.
	if open := rep.Open["docs/CONCEPTS.md"]; len(open) != 1 || open[0].n != 5 || open[0].section != "Scope" || !strings.Contains(open[0].text, "No request goes outside it") {
		t.Errorf("the sentences with no claim: %+v", open)
	}
	for _, p := range rep.Problems {
		if strings.Contains(p, "CONCEPTS") {
			t.Errorf("a page not covered fails: %s", p)
		}
	}
}

// The README and every command page are covered with no @cover line: a page
// added later cannot begin with a claim that has no proof.
func TestACommandPageIsAlwaysCovered(t *testing.T) {
	root := tree(t, "# azhaq\n\nIt never sends a write.\n", page, "")
	if err := os.WriteFile(filepath.Join(root, "docs", "commands", "new.md"), []byte("# azhaq new\n\n## What it does\n\nIt writes nothing else.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rep.Problems, "\n")
	for _, want := range []string{"README.md:3: a claim with no proof", "run.md:5: a claim with no proof", "new.md:5: a claim with no proof"} {
		if !strings.Contains(got, want) {
			t.Errorf("no problem says %q:\n%s", want, got)
		}
	}
}

func TestARewordedClaimFails(t *testing.T) {
	ledger := "@cover docs/commands/run.md\nrun.no-writes\tdocs/commands/run.md\tNever sends a POST without its flag\ttest:cmd/azhaq:TestKeepsScope\n"
	if got := problems(t, "# azhaq\n", page, ledger); !strings.Contains(got, "no longer in docs/commands/run.md") {
		t.Errorf("a claim whose text is gone passes:\n%s", got)
	}
}

func TestAGoneProofFails(t *testing.T) {
	for proof, want := range map[string]string{
		"test:cmd/azhaq:TestRenamed": "TestRenamed is not a test in cmd/azhaq",
		"bench:no such check":        "no bench check says",
		"file:scripts/gone.sh":       "scripts/gone.sh is gone",
		"note:no":                    "says why",
		"guess":                      "want test:DIR:Name",
	} {
		ledger := "run.no-writes\tdocs/commands/run.md\tNever sends a write without its flag\t" + proof + "\n"
		if got := problems(t, "# azhaq\n", page, ledger); !strings.Contains(got, want) {
			t.Errorf("proof %q: want %q in:\n%s", proof, want, got)
		}
	}
}

func TestLedgerRowsAreChecked(t *testing.T) {
	ledger := "run.three\tdocs/commands/run.md\tonly three fields\n" + "bad id\tdocs/commands/run.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope\n" +
		"run.a\tdocs/commands/run.md\tshort\ttest:cmd/azhaq:TestKeepsScope\n" +
		"run.a\tdocs/commands/run.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope\n" +
		"readme.b\tdocs/commands/run.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope\n" +
		"run.c\tdocs/commands/gone.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope\n"
	got := problems(t, "# azhaq\n", page, ledger)
	for _, want := range []string{"want id, file, text and proof", "too short", "in the ledger twice", "the id starts with the page it is about, run.", "is not README.md or a page of docs/ or docs/commands"} {
		if !strings.Contains(got, want) {
			t.Errorf("no problem says %q:\n%s", want, got)
		}
	}
}

// A claim proves the sentences its text touches, not the ones beside it.
func TestASentenceBesideAProvedOneNeedsItsOwnProof(t *testing.T) {
	pg := "# azhaq run\n\n## What it does\n\nIt never sends a write without its flag. It always asks the scope first.\n"
	ledger := "@cover docs/commands/run.md\nrun.no-writes\tdocs/commands/run.md\tnever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope\n"
	got := problems(t, "# azhaq\n", pg, ledger)
	if !strings.Contains(got, "run.md:5: a claim with no proof") || !strings.Contains(got, "It always asks the scope first") || strings.Contains(got, "never sends a write") {
		t.Errorf("want the second sentence alone:\n%s", got)
	}
	ledger += "run.scope\tdocs/commands/run.md\tIt always asks the scope first\ttest:cmd/azhaq:TestKeepsScope\n"
	if got := problems(t, "# azhaq\n", pg, ledger); got != "" {
		t.Errorf("both sentences have a proof:\n%s", got)
	}
}

// @cover FILE#Section holds that section of a page, and not the rest of it.
func TestASectionCoverHoldsOnlyThatSection(t *testing.T) {
	pg := "# Concepts\n\n## Scope\n\nNo request goes outside it.\n\n## Other\n\nNever guess.\n"
	root := tree(t, "# azhaq\n", page, "@cover docs/CONCEPTS.md#Scope\n")
	if err := os.WriteFile(filepath.Join(root, "docs", "CONCEPTS.md"), []byte(pg), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rep.Problems, "\n")
	if !strings.Contains(got, "CONCEPTS.md:5: a claim with no proof") || strings.Contains(got, "CONCEPTS.md:9") {
		t.Errorf("want the Scope claim and not the Other one:\n%s", got)
	}
	if rep.Backlog["docs/CONCEPTS.md"] != 1 {
		t.Errorf("the line outside the section is backlog: %+v", rep.Backlog)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "claims.tsv"), []byte("@cover docs/CONCEPTS.md#Nowhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ = check(root)
	if got := strings.Join(rep.Problems, "\n"); !strings.Contains(got, "no such") {
		t.Errorf("a section that does not exist passes:\n%s", got)
	}
}

// The pages of docs/ are claim pages, and their ids start with docs-.
func TestAPageOfDocsTakesClaims(t *testing.T) {
	pg := "# Concepts\n\n## Scope\n\nNo request goes outside it.\n"
	run := "run.no-writes\tdocs/commands/run.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestKeepsScope\n"
	root := tree(t, "# azhaq\n", page, run+"concepts.scope\tdocs/CONCEPTS.md\tNo request goes outside it\ttest:cmd/azhaq:TestKeepsScope\n")
	if err := os.WriteFile(filepath.Join(root, "docs", "CONCEPTS.md"), []byte(pg), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := check(root)
	if got := strings.Join(rep.Problems, "\n"); !strings.Contains(got, "the id starts with the page it is about, docs-concepts.") {
		t.Errorf("a docs page id with the wrong prefix passes:\n%s", got)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "claims.tsv"), []byte(run+"docs-concepts.scope\tdocs/CONCEPTS.md\tNo request goes outside it\ttest:cmd/azhaq:TestKeepsScope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rep, _ = check(root); len(rep.Problems) != 0 {
		t.Errorf("%v", rep.Problems)
	}
}

// The repository's own README and command pages: every claim of a covered
// page has a proof, and every proof is still there.
func TestRepositoryClaimsHaveProof(t *testing.T) {
	if raceOn {
		// The checks job runs go run ./scripts/claims on every push; under
		// -race this walk of the repository takes about 9 of the 10 minutes.
		t.Skip("the checks job runs the same check without -race")
	}
	rep, err := check("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep.Problems {
		t.Error(p)
	}
	if rep.Claims == 0 {
		t.Error("the ledger is empty")
	}
}

// A test that skips every time proves nothing; one that skips only where a
// tool is missing is still a proof where it runs.
func TestAProofThatAlwaysSkipsFails(t *testing.T) {
	ledger := "run.no-writes\tdocs/commands/run.md\tNever sends a write without its flag\ttest:cmd/azhaq:TestSkipped\n"
	root := tree(t, "# azhaq\n", "# azhaq run\n\n## What it does\n\nNever sends a write without its flag.\n", ledger)
	body := "package main\n\nfunc TestSkipped(t *testing.T) {\n\tt.Skip(\"later\")\n}\n\nfunc TestSometimes(t *testing.T) {\n\tif noChrome {\n\t\tt.Skip(\"no chrome\")\n\t}\n}\n"
	if err := os.WriteFile(filepath.Join(root, "cmd", "azhaq", "b_test.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := check(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rep.Problems, "\n"); !strings.Contains(got, "TestSkipped always skips") {
		t.Errorf("a test that always skips proves a claim:\n%s", got)
	}
	ledger = strings.Replace(ledger, "TestSkipped", "TestSometimes", 1)
	if err := os.WriteFile(filepath.Join(root, "docs", "claims.tsv"), []byte(ledger), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ = check(root)
	if got := strings.Join(rep.Problems, "\n"); strings.Contains(got, "skips") {
		t.Errorf("a test that skips only without Chrome is no proof:\n%s", got)
	}
}
