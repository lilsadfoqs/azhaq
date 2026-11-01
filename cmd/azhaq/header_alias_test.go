package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// -H and -header are one flag on every command that takes either.
func TestHeaderFlagHasBothNames(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = append(seen[r.URL.Path], r.Header.Values("X-Probe")...)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<title>t</title>`))
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	for i, args := range [][]string{
		{"run", "-url", srv.URL + "/run-H", "-no-paths", "-quiet", "-json", "-ledger", "off", "-allow", "127.0.0.1", "-H", "X-Probe: a"},
		{"run", "-url", srv.URL + "/run-header", "-no-paths", "-quiet", "-json", "-ledger", "off", "-allow", "127.0.0.1", "-header", "X-Probe: a"},
		{"probe", "-u", srv.URL + "/probe-H", "-allow", "127.0.0.1", "-H", "X-Probe: a", "-silent"},
		{"probe", "-u", srv.URL + "/probe-header", "-allow", "127.0.0.1", "-header", "X-Probe: a", "-silent"},
		{"crawl", "-u", srv.URL + "/crawl-header", "-allow", "127.0.0.1", "-header", "X-Probe: a", "-silent", "-d", "0"},
	} {
		_, errOut, code := cli(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d\n%s", args, code, errOut)
		}
		path := strings.TrimPrefix(args[2], srv.URL)
		mu.Lock()
		got := seen[path]
		mu.Unlock()
		if len(got) == 0 || got[0] != "a" {
			t.Errorf("case %d %v: the server saw X-Probe %v at %s", i, args, got, path)
		}
	}
}

// A secret header given as -H is no more kept for resume than one given
// as -header.
func TestHeaderAliasIsNotKeptForResume(t *testing.T) {
	got := keptArgs([]string{"-url", "http://a.test/", "-H", "Authorization: Bearer s3cret", "-H", "X-Trace: 1"})
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "s3cret") || !strings.Contains(joined, "-header=X-Trace: 1") {
		t.Errorf("kept %q", joined)
	}
}
