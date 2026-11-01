package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// -max-names caps what guessing asks too: the -w words and the -permute
// variations together. With 2 the run asks 2 names, prints at most 2, and
// stops with exit 4 naming the cap and what it held back; without it every
// word and variation is asked.
func TestSubsPermuteHoldsToMaxNames(t *testing.T) {
	live := []string{"api.example.org", "dev.example.org", "www.example.org", "mail.example.org", "app.example.org"}
	resolver, asked := slowResolver(t, time.Millisecond, live...)
	words := writeFile(t, t.TempDir(), "words.txt", "api\ndev\nwww\nmail\napp\nnope1\nnope2\n")
	t.Chdir(t.TempDir())
	base := []string{"subs", "-d", "example.org", "-w", words, "-permute", "-sources", "none", "-live", "-resolvers", resolver, "-dns-rate", "0", "-no-history"}

	out, rep, code := runContract(t, append(base, "-max-names", "2")...)
	if rows := len(strings.Fields(out)); rows > 2 || rep.Results > 2 {
		t.Errorf("-max-names 2 printed %d rows (%d results):\n%s", rows, rep.Results, out)
	}
	if code != exitLimit || !strings.Contains(rep.Stopped, "-max-names 2 reached") {
		t.Errorf("exit %d, stopped %q: the cap held work back and says so", code, rep.Stopped)
	}
	if rep.Counts["asked by guessing"] != 2 || rep.Counts["guesses held back by -max-names"] < 100 {
		t.Errorf("counts %v: 2 guesses asked and the rest held back", rep.Counts)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), fmt.Sprintf("-max-names 2 held back %d guesses", rep.Counts["guesses held back by -max-names"])) {
		t.Errorf("no note names the cap: %v", rep.Notes)
	}
	if n := asked.Load(); n > 12 {
		t.Errorf("the resolver was asked %d times for a cap of 2 names (wildcard probes and checks included)", n)
	}

	// No -max-names: nothing is held back, whatever the number of guesses.
	_, rep, code = runContract(t, base...)
	if code != exitOK || rep.Stopped != "" || rep.Counts["guesses held back by -max-names"] != 0 || rep.Counts["asked by guessing"] < 500 {
		t.Errorf("without -max-names: exit %d, stopped %q, counts %v", code, rep.Stopped, rep.Counts)
	}
}
