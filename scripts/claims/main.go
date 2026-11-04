// Command claims checks that what the README and the command pages claim has
// a proof: docs/claims.tsv ties each claim to a test or a bench check, and
// this fails when a claim has none, when its text is gone from the page, or
// when its proof is gone from the code.
//
//	go run ./scripts/claims
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

func main() {
	root, list := ".", []string(nil)
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "-list" {
		list, args = args[1:], nil // the pages whose unproved sentences to print
	}
	if len(args) > 0 {
		root = args[0]
	}
	rep, err := check(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "claims:", err)
		os.Exit(2)
	}
	if list != nil {
		for _, f := range list {
			for _, o := range rep.Open[f] {
				fmt.Printf("%s:%d: [%s] %s\n", f, o.n, o.section, o.text)
			}
		}
		return
	}
	fmt.Print(rep.text())
	if len(rep.Problems) > 0 {
		os.Exit(1)
	}
}

// claim is one row of the ledger.
type claim struct {
	ID, File, Text, Proof string
	line                  int
}

type report struct {
	Claims   int
	Proved   map[string]int // proof kind → claims
	Problems []string
	Backlog  map[string]int         // page not yet covered → lines that read as claims
	Open     map[string][]claimLine // page → its sentences that read as claims and have no claim (-list)
}

func (r *report) text() string {
	var b strings.Builder
	for _, p := range r.Problems {
		fmt.Fprintln(&b, "claims:", p)
	}
	kinds := make([]string, 0, len(r.Proved))
	for k := range r.Proved {
		kinds = append(kinds, fmt.Sprintf("%d %s", r.Proved[k], k))
	}
	sort.Strings(kinds)
	fmt.Fprintf(&b, "claims: %d in the ledger (%s); %d problems\n", r.Claims, strings.Join(kinds, ", "), len(r.Problems))
	if len(r.Backlog) > 0 {
		pages := make([]string, 0, len(r.Backlog))
		total := 0
		for f, n := range r.Backlog {
			pages = append(pages, fmt.Sprintf("%s %d", f, n))
			total += n
		}
		sort.Strings(pages)
		fmt.Fprintf(&b, "claims: pages not yet covered, with the lines that read as claims (%d): %s\n", total, strings.Join(pages, ", "))
	}
	return b.String()
}

// trigger marks a line that makes a claim a review can prove false: an
// absolute, a limit, an exit code, a refusal.
var trigger = lazyre.New(`(?i)\b(never|always|every|only|nothing|exactly|at most|at least|no request|exit [0-9]|cannot|without|all|any|not)\b`)

// linkTarget is the address of a markdown link: a heading's slug in it is not a claim.
var linkTarget = lazyre.New(`\]\([^)]*\)`)

func triggers(s string) bool { return trigger.MatchString(linkTarget.ReplaceAllString(s, "]")) }

var idRE = lazyre.New(`^[a-z0-9]+(-[a-z0-9]+)*\.[a-z0-9]+(-[a-z0-9]+)*$`)

// claimFiles are the pages the ledger is about: the README, the pages of
// docs/ that tell a user what to expect (ARCHITECTURE.md is how the code
// works) and every command page.
func claimFiles(root string) []string {
	files := []string{"README.md"}
	for _, dir := range []string{"docs", "docs/commands"} {
		pages, _ := filepath.Glob(filepath.Join(root, dir, "*.md"))
		sort.Strings(pages)
		for _, p := range pages {
			rel, _ := filepath.Rel(root, p)
			if rel = filepath.ToSlash(rel); rel != "docs/ARCHITECTURE.md" {
				files = append(files, rel)
			}
		}
	}
	return files
}

// pagePrefix is what the id of a claim about a page starts with: the page's
// name, and docs- before it for a page of docs/ (docs/MCP.md and
// docs/commands/mcp.md are two pages).
func pagePrefix(file string) string {
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(file), ".md"))
	if filepath.Dir(file) == "docs" {
		return "docs-" + name
	}
	return name
}

// A line of a page that reads as a claim, with the "## " section it is in.
type claimLine struct {
	n             int
	text, section string
}

// sentences cuts a line where a sentence ends and another begins: a full
// stop, question or exclamation mark, then a space and a capital, a quote or
// a code span.
func sentences(line string) [][2]int {
	var out [][2]int
	start := 0
	for i := 0; i+2 < len(line); i++ {
		if (line[i] == '.' || line[i] == '?' || line[i] == '!') && line[i+1] == ' ' {
			if c := line[i+2]; c >= 'A' && c <= 'Z' || c == '`' || c == '*' || c == '"' {
				out = append(out, [2]int{start, i + 1})
				start = i + 2
			}
		}
	}
	return append(out, [2]int{start, len(line)})
}

// claimLines are the lines of a page that read as claims: prose and list
// items outside the synopsis, examples and flag tables (the flag tables are
// made from the binary and the examples are run by tests), code, tables
// and headings.
func claimLines(text string) []claimLine {
	var out []claimLine
	incode := false
	section := ""
	for i, l := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(l, "```"):
			incode = !incode
			continue
		case incode:
			continue
		case strings.HasPrefix(l, "#"):
			if strings.HasPrefix(l, "## ") {
				section = strings.TrimPrefix(l, "## ")
			}
			continue
		}
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "|") || strings.HasPrefix(t, "<!--") {
			continue
		}
		switch section {
		case "Synopsis", "Examples", "Flags":
			continue
		}
		if triggers(t) {
			out = append(out, claimLine{i + 1, t, section})
		}
	}
	return out
}

func readClaims(root string) (claims []claim, covered []string, problems []string, err error) {
	raw, err := os.ReadFile(filepath.Join(root, "docs", "claims.tsv"))
	if err != nil {
		return nil, nil, nil, err
	}
	seen := map[string]bool{}
	for i, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(l, "@cover"); ok {
			if strings.Contains(rest, "#") {
				covered = append(covered, strings.TrimSpace(rest)) // FILE#Section: one spec, spaces and all
			} else {
				covered = append(covered, strings.Fields(rest)...)
			}
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 4 {
			problems = append(problems, fmt.Sprintf("docs/claims.tsv:%d: want id, file, text and proof separated by tabs, got %d fields", i+1, len(f)))
			continue
		}
		c := claim{ID: f[0], File: f[1], Text: f[2], Proof: f[3], line: i + 1}
		switch {
		case !idRE.MatchString(c.ID):
			problems = append(problems, fmt.Sprintf("docs/claims.tsv:%d: %q is not an id (page.claim, lower case and hyphens)", c.line, c.ID))
		case seen[c.ID]:
			problems = append(problems, fmt.Sprintf("docs/claims.tsv:%d: %s is in the ledger twice", c.line, c.ID))
		}
		seen[c.ID] = true
		claims = append(claims, c)
	}
	return claims, covered, problems, nil
}

// A proof is one spec or several joined by ";" (each must hold). The kinds:
// test:DIR:Name[,Name] (each a Test function in DIR's tests, none that always skips),
// bench:TEXT (TEXT is in a check name of the bench), file:PATH (a script or
// a record that exists), note:WHY (the line is advice, a pointer or a
// definition, not a behaviour a test can hold).
func checkProof(root string, c claim, cache map[string]string) (kind, problem string) {
	for i, spec := range strings.Split(c.Proof, ";") {
		k, p := checkSpec(root, strings.TrimSpace(spec), cache)
		if i == 0 {
			kind = k
		}
		if p != "" {
			return k, p
		}
	}
	return kind, ""
}

func checkSpec(root, spec string, cache map[string]string) (kind, problem string) {
	kind, rest, _ := strings.Cut(spec, ":")
	switch kind {
	case "test":
		dir, names, ok := strings.Cut(rest, ":")
		if !ok || names == "" {
			return kind, "proof test: needs DIR:Name"
		}
		src := readDir(root, dir, "_test.go", cache)
		for _, n := range strings.Split(names, ",") {
			at := regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(n) + `\(`).FindStringIndex(src)
			if at == nil {
				return kind, fmt.Sprintf("its proof %s is not a test in %s", n, dir)
			}
			body := src[at[0]:]
			if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
				body = body[:end+1]
			}
			if regexp.MustCompile(`(?m)^\tt\.Skip`).MatchString(body) {
				return kind, fmt.Sprintf("its proof %s always skips: a test that does not run proves nothing", n)
			}
		}
	case "bench":
		src := readDir(root, "bench", ".go", cache)
		if rest == "" || !strings.Contains(src, rest) {
			return kind, fmt.Sprintf("no bench check says %q", rest)
		}
	case "file":
		if _, err := os.Stat(filepath.Join(root, rest)); err != nil {
			return kind, fmt.Sprintf("its proof file %s is gone", rest)
		}
	case "note":
		if len(strings.Fields(rest)) < 3 {
			return kind, "a note says why the line is not a behaviour claim"
		}
	default:
		return kind, fmt.Sprintf("proof %q: want test:DIR:Name, bench:TEXT, file:PATH or note:WHY", spec)
	}
	return kind, ""
}

func readDir(root, dir, suffix string, cache map[string]string) string {
	key := dir + suffix
	if s, ok := cache[key]; ok {
		return s
	}
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(root, dir, "*"+suffix))
	for _, f := range files {
		if suffix == ".go" && strings.HasSuffix(f, "_test.go") {
			continue
		}
		if raw, err := os.ReadFile(f); err == nil {
			b.Write(raw)
			b.WriteByte('\n')
		}
	}
	cache[key] = b.String()
	return cache[key]
}

// isCovered says whether a line of file, in section, must have its claims
// proved: its whole page is under @cover, or its "## " section is
// (FILE#Section).
func isCovered(covered []string, file, section string) bool {
	return slices.Contains(covered, file) || slices.Contains(covered, file+"#"+section)
}

// unproved are the sentences of a line that read as claims and that no claim
// of the page touches: a claim holds the sentences its text overlaps, so one
// claim cannot stand for the sentences beside it.
func unproved(line string, claims []claim, file string) []string {
	var held [][2]int
	for _, c := range claims {
		if c.File != file {
			continue
		}
		for from := 0; ; {
			i := strings.Index(line[from:], c.Text)
			if i < 0 {
				break
			}
			held = append(held, [2]int{from + i, from + i + len(c.Text)})
			from += i + 1
		}
	}
	var out []string
	for _, r := range sentences(line) {
		sentence := line[r[0]:r[1]]
		if !triggers(sentence) {
			continue
		}
		if !slices.ContainsFunc(held, func(h [2]int) bool { return h[0] < r[1] && r[0] < h[1] }) {
			out = append(out, sentence)
		}
	}
	return out
}

func check(root string) (*report, error) {
	claims, covered, problems, err := readClaims(root)
	if err != nil {
		return nil, err
	}
	rep := &report{Claims: len(claims), Proved: map[string]int{}, Problems: problems, Backlog: map[string]int{}, Open: map[string][]claimLine{}}
	files := claimFiles(root)
	pages := map[string][]claimLine{}
	texts := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, err
		}
		texts[f] = string(raw)
		pages[f] = claimLines(string(raw))
	}
	cache := map[string]string{}
	for _, c := range claims {
		at := fmt.Sprintf("docs/claims.tsv:%d: %s", c.line, c.ID)
		if page := pagePrefix(c.File); !strings.HasPrefix(c.ID, page+".") {
			rep.Problems = append(rep.Problems, at+": the id starts with the page it is about, "+page+".")
		}
		text, ok := texts[c.File]
		switch {
		case !ok:
			rep.Problems = append(rep.Problems, at+": "+c.File+" is not README.md or a page of docs/ or docs/commands")
		case len(c.Text) < 12:
			rep.Problems = append(rep.Problems, at+": the text is too short to find the claim by")
		case !strings.Contains(text, c.Text):
			rep.Problems = append(rep.Problems, at+": the text is no longer in "+c.File+" (the claim was reworded: prove it again and update the ledger): "+c.Text)
		}
		kind, problem := checkProof(root, c, cache)
		if problem != "" {
			rep.Problems = append(rep.Problems, at+": "+problem)
		} else {
			rep.Proved[kind]++
		}
	}
	for _, f := range files {
		for _, l := range pages[f] {
			open := unproved(l.text, claims, f)
			if len(open) == 0 {
				continue
			}
			rep.Open[f] = append(rep.Open[f], claimLine{l.n, strings.Join(open, " "), l.section})
			if isCovered(covered, f, l.section) {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s:%d: a claim with no proof (add it to docs/claims.tsv with a test, or reword it): %s", f, l.n, clip(open[0])))
			} else {
				rep.Backlog[f]++
			}
		}
	}
	for _, spec := range covered {
		f, section, hasSection := strings.Cut(spec, "#")
		text, ok := texts[f]
		switch {
		case !ok:
			rep.Problems = append(rep.Problems, "docs/claims.tsv: @cover names "+f+", which is not README.md or a page of docs/ or docs/commands")
		case hasSection && !strings.Contains("\n"+text, "\n## "+section+"\n"):
			rep.Problems = append(rep.Problems, "docs/claims.tsv: @cover names the section "+section+" of "+f+", which has no such \"## \" heading")
		}
	}
	return rep, nil
}

func clip(s string) string {
	if len(s) > 140 {
		return s[:140] + "…"
	}
	return s
}
