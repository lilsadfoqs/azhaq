package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A comma ends a URL only before the next scheme; a comma in a path or query
// stays; a piece with no / ? # is a host list and splits at every comma.
func TestSplitURLList(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"http://h/a,http://h/b,https://h/c", []string{"http://h/a", "http://h/b", "https://h/c"}},
		{"http://h/?a=1,2", []string{"http://h/?a=1,2"}},
		{"http://h/x,y", []string{"http://h/x,y"}},
		{"http://h/?a=1,2,HTTP://h2/p?b=3,4", []string{"http://h/?a=1,2", "HTTP://h2/p?b=3,4"}},
		{"a.example,b.example:8080, 192.0.2.1", []string{"a.example", "b.example:8080", "192.0.2.1"}},
		{"a.example,http://b.example/", []string{"a.example", "http://b.example/"}},
		{"http://h/a, http://h/b", []string{"http://h/a", "http://h/b"}},
		{"", nil},
	} {
		if got := splitURLList(c.in); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func pathServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if strings.HasSuffix(r.URL.Path, "/admin") {
			fmt.Fprint(w, "<html><title>admin</title>found</html>")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/nothere") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "<html><title>x</title></html>")
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

func seenUnder(seen []string, prefix string) bool {
	for _, s := range seen {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// run, params and dirs ask all three URLs of a comma-joined value, and none
// asks a path that holds the other URLs.
func TestCommaJoinedURLsAreAskedOneByOne(t *testing.T) {
	words := wlist(t, "admin", "nothere")
	for _, c := range []struct {
		cmd  string
		args func(u string) []string
	}{
		{"run", func(u string) []string {
			return []string{"run", "-url", u, "-no-paths", "-no-favicon", "-depth", "0", "-max-requests", "60"}
		}},
		{"params", func(u string) []string {
			return []string{"params", "-u", u, "-w", words, "-rate", "10000", "-allow", "127.0.0.1"}
		}},
		{"dirs", func(u string) []string {
			return []string{"dirs", "-u", u, "-w", words, "-ac=false", "-allow", "127.0.0.1"}
		}},
	} {
		t.Run(c.cmd, func(t *testing.T) {
			srv, seen := pathServer(t)
			u := srv.URL
			joined := u + "/a," + u + "/b," + u + "/c"
			args := append(c.args(joined), "-db", filepath.Join(t.TempDir(), "x.db"), "-ledger", "off", "-json")
			cli(t, args...)
			got := seen()
			for _, p := range []string{"/a", "/b", "/c"} {
				if !seenUnder(got, p) {
					t.Errorf("%s was never asked; the server saw %v", p, got)
				}
			}
			for _, s := range got {
				if strings.Contains(s, "http://") || strings.Contains(s, ",") {
					t.Errorf("a path that holds the other URLs was asked: %q", s)
				}
			}
		})
	}
}

// A comma inside a URL's query is part of it, in every command.
func TestCommaInQueryKeepsURLWhole(t *testing.T) {
	for _, cmd := range []string{"run", "params", "dirs"} {
		t.Run(cmd, func(t *testing.T) {
			srv, seen := pathServer(t)
			u := srv.URL + "/?a=1,2"
			var args []string
			switch cmd {
			case "run":
				args = []string{"run", "-url", u, "-no-paths", "-no-favicon", "-depth", "0", "-max-requests", "20"}
			case "params":
				args = []string{"params", "-u", u, "-w", wlist(t, "zz"), "-rate", "10000", "-allow", "127.0.0.1"}
			case "dirs":
				args = []string{"dirs", "-u", u, "-w", wlist(t, "admin"), "-ac=false", "-allow", "127.0.0.1"}
			}
			cli(t, append(args, "-db", filepath.Join(t.TempDir(), "x.db"), "-ledger", "off", "-json")...)
			got := seen()
			if len(got) == 0 {
				t.Fatal("nothing was asked")
			}
			for _, s := range got {
				if strings.HasPrefix(s, "/2") || strings.Contains(s, "/?2") {
					t.Errorf("the value was cut at its comma: %q", s)
				}
			}
			if cmd != "dirs" && !slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, "a=1,2") || strings.Contains(s, "a=1%2C2") }) {
				t.Errorf("the query a=1,2 was never sent whole: %v", got)
			}
		})
	}
}

// fuzz takes one URL template: a second scheme after a comma is refused,
// and a comma that is no scheme's is kept.
func TestFuzzRefusesAValueWithASecondURL(t *testing.T) {
	srv, seen := pathServer(t)
	w := wlist(t, "a")
	_, errOut, code := cli(t, "fuzz", "-u", srv.URL+"/FUZZ,"+srv.URL+"/FUZZ", "-w", w, "-ledger", "off")
	if code != exitUsage || !strings.Contains(errOut, "-u takes one URL and is not repeatable") {
		t.Errorf("exit %d, stderr %q: want a usage error naming -u", code, errOut)
	}
	if len(seen()) != 0 {
		t.Errorf("a refused value sent %v", seen())
	}
	_, _, code = cli(t, "fuzz", "-u", srv.URL+"/x,FUZZ", "-w", w, "-ledger", "off", "-json")
	if code == exitUsage {
		t.Errorf("a comma in the path was refused")
	}
}

// Every command with a URL flag says it takes a comma list, and the flag
// takes one: help and code agree.
func TestURLFlagsHelpSaysCommaSeparated(t *testing.T) {
	want := map[string]string{"run": "url", "plan": "url", "resume": "", "dirs": "u", "params": "u", "crawl": "u", "probe": "u", "shots": "u"}
	for _, c := range buildManifest().Commands {
		name, ok := want[c.Name]
		if !ok || name == "" {
			continue
		}
		found := false
		for _, f := range c.Flags {
			if f.Name != name {
				continue
			}
			found = true
			if !strings.Contains(f.Usage, "repeatable, or comma-separated") {
				t.Errorf("%s -%s: help %q does not say repeatable, or comma-separated", c.Name, name, f.Usage)
			}
			if !f.Repeatable {
				t.Errorf("%s -%s is not marked repeatable", c.Name, name)
			}
		}
		if !found {
			t.Errorf("%s has no -%s", c.Name, name)
		}
	}
}
