package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// ffuf's -b is the cookie flag of dirs as it is of fuzz: one value holds
// several pairs, and every word of the sweep carries them in one Cookie header.
func TestDirsTakesFfufsCookieFlag(t *testing.T) {
	for _, flag := range []string{"-b", "-cookie"} {
		var mu sync.Mutex
		seen := map[string]string{} // the Cookie header each path was asked with
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[r.URL.Path] = r.Header.Get("Cookie")
			mu.Unlock()
			if r.URL.Path == "/admin" {
				fmt.Fprint(w, "hello world")
				return
			}
			http.NotFound(w, r)
		}))
		out, errOut, err := captureBoth(t, func() error {
			return cmdDirs([]string{"-u", srv.URL + "/", "-w", wlist(t, "admin", "nope"), flag, "PHPSESSID=abc; security=low", "-json", "-ledger", "off", "-db", t.TempDir() + "/d.db"})
		})
		srv.Close()
		if err != nil {
			t.Fatalf("dirs %s: %v\n%s", flag, err, errOut)
		}
		if !strings.Contains(out, "/admin") {
			t.Errorf("dirs %s: no row for /admin:\n%s", flag, out)
		}
		for _, p := range []string{"/admin", "/nope"} {
			if seen[p] != "PHPSESSID=abc; security=low" {
				t.Errorf("dirs %s: %s was asked with Cookie %q, the server saw %v", flag, p, seen[p], seen)
			}
		}
	}
}

// Every ffuf flag a MIGRATING table maps to azhaq's own name for the same
// command is a flag of that command: a section names more than one command,
// and each table names the one it is about.
func TestMigratingFfufFlagsExistInTheirCommand(t *testing.T) {
	doc := readDoc(t, "../../docs/MIGRATING.md")
	var sec string
	for _, s := range regexp.MustCompile(`(?m)^## `).Split(doc, -1) {
		if strings.HasPrefix(s, "ffuf") {
			sec = s
		}
	}
	if sec == "" {
		t.Fatal("no ffuf section")
	}
	var cmd string
	rows := map[string]int{}
	for _, l := range strings.Split(sec, "\n") {
		tl := strings.TrimSpace(l)
		if m := regexp.MustCompile(`^<!-- azhaq: (\S+) -->$`).FindStringSubmatch(tl); m != nil {
			cmd = m[1]
			continue
		}
		if cmd == "" || !strings.HasPrefix(tl, "|") {
			continue
		}
		cells := regexp.MustCompile(`[^\\]\|`).Split(" "+tl, -1)
		if len(cells) < 4 {
			continue
		}
		spans := codeSpans(cells[2])
		if strings.HasPrefix(strings.TrimSpace(cells[2]), "the same") {
			spans = codeSpans(cells[1]) // the ffuf column is the claim
		}
		fs := flagsOf(cmd)
		if fs == nil {
			t.Fatalf("no command %q", cmd)
		}
		for _, sp := range spans {
			for _, w := range strings.Fields(sp) {
				n := docFlagName(w)
				if n == "" || foreignFlags[n] {
					continue
				}
				rows[cmd]++
				if fs.Lookup(n) == nil {
					t.Errorf("MIGRATING maps ffuf -%s to azhaq %s, which has no -%s", n, cmd, n)
				}
			}
		}
	}
	if rows["fuzz"] < 30 || rows["dirs"] < 15 {
		t.Errorf("the walk saw %v flags: the table format changed", rows)
	}
}
