package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// run -max-time bounds the whole run, the DNS brute force and the
// permutations included: a slow resolver and a long wordlist stop at the
// bound with exit 4, naming the flag, and what was not asked is left for
// resume.
func TestRunMaxTimeStopsTheDNSBruteForce(t *testing.T) {
	var ws []string
	for i := 0; i < 60; i++ {
		ws = append(ws, fmt.Sprintf("w%02d", i))
	}
	resolver, asked := slowResolver(t, 100*time.Millisecond)
	words := writeList(t, ws...)
	t.Chdir(t.TempDir())
	t0 := time.Now()
	_, rep, code := runContract(t, "run", "-domain", "example.org", "-sources", "none", "-dns-brute", words, "-permute",
		"-resolvers", resolver, "-dns-rate", "5", "-max-time", "3s", "-no-paths", "-depth", "1", "-no-history", "-db", "m.db")
	if took := time.Since(t0); took > 9*time.Second {
		t.Errorf("-max-time 3s: the run took %s (%d queries; 60 names at 5 a second take 12 s)", took, asked.Load())
	}
	if code != exitLimit || rep.Complete || !strings.Contains(rep.Stopped, "-max-time 3s") {
		t.Errorf("exit %d, stopped %q: a run cut by -max-time is a stop that names the flag", code, rep.Stopped)
	}
}

// What -max-time cut is left for resume, which asks the names the stop kept.
func TestRunMaxTimeLeavesTheBruteForceResumable(t *testing.T) {
	var ws []string
	for i := 0; i < 40; i++ {
		ws = append(ws, fmt.Sprintf("w%02d", i))
	}
	resolver, asked := slowResolver(t, 50*time.Millisecond)
	words := writeList(t, ws...)
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-domain", "example.org", "-sources", "none", "-dns-brute", words,
		"-resolvers", resolver, "-dns-rate", "5", "-max-time", "2s", "-no-paths", "-depth", "0", "-no-history", "-db", "m.db")
	if code != exitLimit || !strings.Contains(rep.Stopped, "tasks known and not done") {
		t.Fatalf("exit %d, stopped %q", code, rep.Stopped)
	}
	first := asked.Load()
	_, rep, code = runContract(t, "resume", "-db", "m.db", "-resolvers", resolver, "-dns-rate", "0", "-no-history")
	if code != exitOK || asked.Load() <= first {
		t.Errorf("resume: exit %d, stopped %q, %d queries after %d", code, rep.Stopped, asked.Load(), first)
	}
}
