package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// shotsCost runs shots on args against a page that has one stylesheet and
// returns the requests the page's server got, the summary and the ledger's
// lines for the target.
func shotsCost(t *testing.T, name, host string, extra ...string) (served []string, sum map[string]any, targets []string) {
	t.Helper()
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = append(served, r.URL.RequestURI())
		mu.Unlock()
		if r.URL.Path == "/a.css" {
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, "h1{color:#246}")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>app</title><link rel=stylesheet href="/a.css"></head><body><h1>hi</h1></body></html>`)
	}))
	defer site.Close()
	su, _ := url.Parse(site.URL)
	target := strings.ReplaceAll(name, "PORT", su.Port())
	dir := t.TempDir()
	led := filepath.Join(dir, "led.jsonl")
	args := append([]string{"shots", "-u", target, "-allow", host, "-dir", filepath.Join(dir, "s"), "-ledger", led, "-json"}, extra...)
	_, errOut, code := cli(t, args...)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	raw, err := os.ReadFile(led)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(raw), "\n") {
		var line struct{ Kind, Class, Target string }
		if json.Unmarshal([]byte(l), &line) == nil && line.Class == "target" {
			targets = append(targets, line.Kind+" "+line.Target)
		}
	}
	return served, sumMap(t, errOut), targets
}

// A page given is asked as given. The name in its URL is not also asked on
// 443 and 80 (two more requests that nothing was told to send, and a note
// that there is no web service there), and every request of the run is one
// the target's server got.
func TestShotsAsksOnlyThePageGiven(t *testing.T) {
	for _, target := range []string{"http://localhost:PORT/", "localhost:PORT"} {
		t.Run(target, func(t *testing.T) {
			served, sum, targets := shotsCost(t, target, "localhost")
			for _, l := range targets {
				if strings.Contains(l, "https://localhost/") || strings.Contains(l, "http://localhost/") {
					t.Errorf("a request to a port nobody named: %s\nall: %v", l, targets)
				}
			}
			if notes := fmt.Sprint(sum["notes"]); strings.Contains(notes, "no web service") {
				t.Errorf("a note says there is no web service where nothing was asked: %s", notes)
			}
			// A URL is one scheme: what the summary counts is what the server got.
			if n := int(sum["requests"].(float64)); strings.Contains(target, "://") && n != len(served) {
				t.Errorf("the summary counts %d requests, the server got %d: %v", n, len(served), served)
			}
		})
	}
}

// A bare name is a name to find the web services of: it is asked on 443 and 80.
func TestShotsBareNameIsStillAskedOnTheWebPorts(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	led := filepath.Join(dir, "led.jsonl")
	_, errOut, _ := cli(t, "shots", "-u", "localhost", "-allow", "localhost", "-dir", filepath.Join(dir, "s"), "-ledger", led, "-json", "-timeout", "20s")
	raw, _ := os.ReadFile(led)
	if !strings.Contains(string(raw), `"target":"https://localhost/"`) {
		t.Errorf("a bare name was not asked on 443:\n%s\n%s", raw, errOut)
	}
}
