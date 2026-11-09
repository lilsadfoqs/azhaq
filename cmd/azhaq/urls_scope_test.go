package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// urls takes -allow, -deny and -scope as dns does: a URL on a host they hold
// out is not listed, gets no request with -live and is counted as held out by
// scope.
func TestURLsDenyKeepsAHostOutOfTheLiveCheck(t *testing.T) {
	t.Chdir(t.TempDir())
	flags, _ := archiveMirror(t)
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxy.Close)
	args := append([]string{"urls", "-d", "example.org", "-subs", "-json", "-urls-pause", "0", "-live", "-live-rate", "50", "-live-proxy", proxy.URL,
		"-deny", "api.example.org", "-ledger", "l.jsonl", "-db", filepath.Join(t.TempDir(), "u.db")}, flags...)
	out, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if strings.Contains(out, "api.example.org") {
		t.Errorf("a denied host is listed:\n%s", out)
	}
	if !strings.Contains(out, "www.example.org/w") {
		t.Errorf("an allowed host is missing:\n%s", out)
	}
	for _, u := range seen {
		if strings.Contains(u, "api.example.org") {
			t.Errorf("a denied host was asked: %s", u)
		}
	}
	if len(seen) == 0 {
		t.Errorf("the live check asked nothing")
	}
	if err := ledger.Read("l.jsonl", func(e ledger.Entry) error {
		if strings.Contains(e.Target, "api.example.org") || strings.Contains(e.Host, "api.example.org") {
			t.Errorf("a denied host has a ledger line: %+v", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rep := lastReport(t, errOut)
	if rep.Counts["held out by scope"] != 1 {
		t.Errorf("counts %v: want the one URL of api.example.org held out by scope", rep.Counts)
	}
}
