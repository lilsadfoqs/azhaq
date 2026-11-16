package main

import (
	"regexp"
	"strings"
	"testing"
)

// A command's help names only flags the command has, or flags tied by name
// to another command ("crawl's -no-form-fill", "azhaq ledger -verify") or to
// another tool ("as ffuf's -ac"). A bare "-flag" the command rejects sends
// the reader to an error.

var helpFlagMention = regexp.MustCompile("(?:^|[\\s(\"'`,;=/])--?([A-Za-z][A-Za-z0-9-]*)")

// helpForeignTools are the tools the help compares azhaq to.
var helpForeignTools = map[string]bool{
	"subfinder": true, "ffuf": true, "arjun": true, "katana": true, "naabu": true, "nmap": true,
	"nuclei": true, "gau": true, "gowitness": true, "httpx": true, "dnsx": true, "asnmap": true,
}

// helpTie is the name a mention is tied to: the word before it, past other
// flags and "or"/"and" ("ledger -verify -seal" is tied to ledger).
func helpTie(text string, at int) string {
	words := strings.Fields(strings.NewReplacer("(", " ", "/", " ").Replace(text[:at]))
	for i := len(words) - 1; i >= 0; i-- {
		w := strings.ToLower(strings.Trim(strings.TrimSuffix(words[i], "'s"), "\"'`,;:.)"))
		if strings.HasPrefix(w, "-") || w == "or" || w == "and" {
			continue
		}
		return w
	}
	return ""
}

func helpFlagProblems(ft flagTable, c commandInfo) []string {
	texts := []string{c.Summary, c.Usage, c.Like, c.Output}
	for _, f := range c.Flags {
		texts = append(texts, f.Usage)
	}
	var bad []string
	for _, text := range texts {
		for _, m := range helpFlagMention.FindAllStringSubmatchIndex(text, -1) {
			name := text[m[2]:m[3]]
			if ft.byCmd[c.Name][name] {
				continue
			}
			tie := helpTie(text, m[2]-1)
			if helpForeignTools[tie] || (ft.byCmd[tie] != nil && tie != c.Name && ft.byCmd[tie][name]) {
				continue
			}
			bad = append(bad, "-"+name+": ..."+text[max(0, m[0]-40):min(len(text), m[3]+10)])
		}
	}
	return bad
}

func TestHelpNamesOnlyFlagsOfItsCommand(t *testing.T) {
	ft := newFlagTable()
	for _, c := range buildManifest().Commands {
		for _, b := range helpFlagProblems(ft, c) {
			t.Errorf("help %s names a flag it does not take: %s", c.Name, b)
		}
	}
}

func TestHelpFlagCheckCatchesABadFlag(t *testing.T) {
	ft := newFlagTable()
	c := commandInfo{Name: "ledger", Summary: "-no-form-fill turns it off; crawl's -no-form-fill does; as ffuf's -ac does; azhaq crawl -fill-forms; azhaq ledger -verify -seal; -verify or -nope"}
	got := strings.Join(helpFlagProblems(ft, c), "\n")
	for _, want := range []string{"-no-form-fill: ...-no-form-fill turns", "-fill-forms", "-nope"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if n := strings.Count(got, "\n") + 1; n != 3 {
		t.Errorf("%d problems, want 3:\n%s", n, got)
	}
}
