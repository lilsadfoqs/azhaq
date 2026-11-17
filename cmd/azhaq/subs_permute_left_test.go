package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A stopped -permute job's note adds up: the names asked, the ones not asked
// and the ones the scope held out are the "variation names to ask". With the
// URL's host as the only name in scope, the scope holds out most of them, and
// -max-names holds back some of the rest.
func TestRunPermuteNoteAddsUpToTheVariationNames(t *testing.T) {
	resolver, _ := slowResolver(t, time.Millisecond, "app.example.com")
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-url", "http://app.example.com/", "-permute", "-sources", "none", "-resolvers", resolver,
		"-no-history", "-db", "p.db", "-max-names", "20", "-max-requests", "10")
	if code != exitLimit {
		t.Fatalf("exit %d, stopped %q", code, rep.Stopped)
	}
	var note string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "-permute: ") {
			note = n
		}
	}
	num := func(re string) int {
		m := regexp.MustCompile(re).FindStringSubmatch(note)
		if m == nil {
			t.Fatalf("no %q in %q", re, note)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	all, asked, left, out := num(`(\d+) variation names to ask`), num(`(\d+) asked`), num(`(\d+) not asked when the run stopped`), num(`(\d+) held out by the scope`)
	if asked != 20 || asked+left+out != all {
		t.Errorf("%d asked + %d not asked + %d held out by the scope is not the %d to ask: %q", asked, left, out, all, note)
	}
	if want := fmt.Sprintf("-max-names 20 held back %d guesses", left); !strings.Contains(strings.Join(rep.Notes, "\n"), want) {
		t.Errorf("the cap's note does not say %q: %v", want, rep.Notes)
	}
}
