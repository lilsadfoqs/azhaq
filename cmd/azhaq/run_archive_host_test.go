package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// hostArchive is a Wayback fixture that says what it was asked for and
// lists one archived URL of www.example.org.
func hostArchive(t *testing.T) (flag string, asked func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wayback" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("page") != "0" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, r.URL.Query().Get("url"))
		mu.Unlock()
		fmt.Fprint(w, `[["original"],["http://www.example.org/archived"]]`)
	}))
	t.Cleanup(srv.Close)
	return "wayback=" + srv.URL + "/wayback", func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

// A run whose scope names a host and not its domain asks the archives for
// the host and lists its archived URLs; a scope that holds the domain asks
// for the domain and its subdomains as before.
func TestRunScopeOfAHostAsksTheArchivesForIt(t *testing.T) {
	for _, tc := range []struct{ allow, want string }{
		{"www.example.org", "www.example.org/*"},
		{"example.org", "*.example.org/*"},
	} {
		t.Run(tc.allow, func(t *testing.T) {
			flag, asked := hostArchive(t)
			t.Chdir(t.TempDir())
			out, rep, code := runContract(t, "run", "-list", hostsFile(t, "www.example.org"), "-passive", "-depth", "0",
				"-skip", skipAllBut("azhaq-urls"), "-urls-sources", "wayback", "-urls-archive", flag, "-urls-pause", "0",
				"-allow", tc.allow, "-db", "d.db")
			if code != exitOK {
				t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
			}
			if got := asked(); !slices.Equal(got, []string{tc.want}) {
				t.Errorf("the archive was asked for %q, want %q", got, tc.want)
			}
			if !strings.Contains(out, "http://www.example.org/archived") {
				t.Errorf("the archived URL is not in the rows:\n%s", out)
			}
		})
	}
}
