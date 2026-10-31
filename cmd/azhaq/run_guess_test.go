package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/types"
)

// run -dns-brute with no passive source and -depth 0 does not go on to
// resolve the names it finds, and does not need to: DNS answered each one
// when it was guessed, so the map holds them live with their addresses.
func TestRunKeepsTheAnswersOfTheNamesItGuessed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DATA_DIR", dir)
	resolvers := serveZone(t, fakeZone{
		a:     map[string]string{"app.example.com": "192.0.2.1", "dev.example.com": "192.0.2.2"},
		cname: map[string]string{"www.example.com": "app.example.com"},
	})
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("app\ndev\nwww\nnope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := cli(t, "run", "-domain", "example.com", "-dns-brute", words, "-permute", "-sources", "none",
		"-resolvers", resolvers, "-no-paths", "-depth", "0", "-db", "r.db",
		"-skip", skipAllBut("azhaq-subdomains", "azhaq-dns", "azhaq-dns-brute", "azhaq-permute"))
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, want := range []string{"app.example.com  target  live  ips=[192.0.2.1]", "dev.example.com  target  live  ips=[192.0.2.2]"} {
		if !strings.Contains(out, want) {
			t.Errorf("the map lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not resolved in this run") || strings.Contains(out, "unresolved") {
		t.Errorf("names DNS answered are listed as not resolved:\n%s", out)
	}
	rows, _, _ := cli(t, "query", "-db", "r.db", "-type", "Hostname", "-json")
	for name, ip := range map[string]string{"app.example.com": "192.0.2.1", "dev.example.com": "192.0.2.2"} {
		var line string
		for _, l := range strings.Split(rows, "\n") {
			if strings.Contains(l, `"key":"`+name+`"`) {
				line = l
			}
		}
		if !strings.Contains(line, `"role":"live"`) || !strings.Contains(line, ip) {
			t.Errorf("%s is not a live row with %s: %s", name, ip, line)
		}
	}
}

// run -permute varies every name the run found, as subs -permute does: the
// brute-forced one and the CNAME target its answer named.
func TestRunPermutesTheNamesTheBruteForceFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AZHAQ_DATA_DIR", dir)
	resolvers := serveZone(t, fakeZone{
		a: map[string]string{"dev.example.com": "192.0.2.2", "staging.example.com": "192.0.2.3", "app.example.com": "192.0.2.4",
			"mail.example.com": "192.0.2.5", "vpn.example.com": "192.0.2.6", "www.example.com": "192.0.2.7", "api1.example.com": "192.0.2.8", "lb.example.com": "192.0.2.9"},
		cname: map[string]string{"api.example.com": "lb.example.com"},
	})
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("api\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := cli(t, "run", "-domain", "example.com", "-sources", "none", "-dns-brute", words, "-permute",
		"-resolvers", resolvers, "-dns-rate", "0", "-no-paths", "-depth", "1", "-db", "r.db", "-no-history",
		"-skip", skipAllBut("azhaq-subdomains", "azhaq-dns", "azhaq-dns-brute", "azhaq-permute"))
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, n := range []string{"api", "dev", "staging", "mail", "vpn", "www", "api1"} {
		if !strings.Contains(out, n+".example.com") {
			t.Errorf("the map lacks %s.example.com:\n%s", n, out)
		}
	}
}

// The note on names -permute could not reach counts what stayed past -depth
// unresolved: not the names a guessing technique resolved, nor what a
// variation found.
func TestUnvariedCountsNamesPastDepthThatNothingResolved(t *testing.T) {
	host := func(n string, kv ...string) types.Seed {
		k := map[string]string{"fqdn": n}
		for i := 0; i < len(kv); i += 2 {
			k[kv[i]] = kv[i+1]
		}
		return types.Seed{Type: types.TypeHostname, Keys: k}
	}
	left := []types.Seed{
		host("a.example.com"), host("b.example.com"),
		host("api.example.com", types.LiveKey, "1"),
		host("dev.example.com", types.ViaKey, types.ViaPermute),
		host("example.com"),
		{Type: types.TypeURL, Keys: map[string]string{"url": "https://c.example.com/"}},
	}
	if n := unvaried(left); n != 2 {
		t.Errorf("unvaried %d, want 2 (a and b)", n)
	}
}
