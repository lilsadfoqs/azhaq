package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// identityApp is an app that does not change between two runs, but whose
// pages carry what changes with every visit: the order of the query names of
// its links, a Seam conversation id, and an anti-forgery token that Joomla
// uses as a form field's name.
func identityApp(t *testing.T) (srv *httptest.Server, asked func() []string) {
	t.Helper()
	var visit atomic.Int32
	var mu sync.Mutex
	var raw []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		raw = append(raw, r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			n := visit.Add(1)
			a, b := "sort=name", "order=asc"
			if n%2 == 0 {
				a, b = b, a
			}
			fmt.Fprintf(w, `<html><title>home</title>
<a href="/list.php?%s&%s">list</a>
<a href="/login.seam?conversationId=%d">sign in</a>
<a href="/join">join</a></html>`, a, b, 10+int(n)*7)
		case "/join":
			tok := make([]byte, 16)
			_, _ = rand.Read(tok)
			fmt.Fprintf(w, `<html><title>join</title><form method="post" action="/join">
<input name="username"><input name="password"><input type="hidden" name="%s" value="1"></form></html>`, hex.EncodeToString(tok))
		default:
			fmt.Fprintf(w, `<html><title>%s</title></html>`, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), raw...)
	}
}

// diffOfTwoRuns runs the app twice into one workspace and returns what diff
// says of the second against the first.
func diffOfTwoRuns(t *testing.T, srv *httptest.Server) (rows map[string][]string, sum map[string]any) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "ws.db")
	for range 2 {
		fetch.Reset()
		fetch.SetProbeToken(fetch.RandomName())
		args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-quiet", "-db", db}
		if _, errOut, err := captureBoth(t, func() error { return cmdRun(args) }); err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
	}
	out, errOut, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows = map[string][]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		k := m["kind"].(string)
		if k == "summary" {
			sum = m
			continue
		}
		rows[k] = append(rows[k], l)
	}
	return rows, sum
}

// Two runs of an app that changed nothing diff empty, whatever order its
// links write their query names in, whichever conversation id they carry and
// whichever name the form's token field has.
func TestDiffOfAnUnchangedAppIgnoresWhatChangesPerVisit(t *testing.T) {
	srv, _ := identityApp(t)
	rows, sum := diffOfTwoRuns(t, srv)
	if sum == nil || sum["added"] != 0.0 || sum["removed"] != 0.0 || sum["observations"] != 0.0 || sum["changed"] != 0.0 {
		t.Fatalf("two runs of an unchanged app differ: %v\n%v", sum, rows)
	}
	if sum["paired_urls"] != 1.0 {
		t.Errorf("the conversation id URL is not counted as one paired URL: %v", sum)
	}
}

// The text report says how many URLs were counted as one by their numbers.
func TestDiffTextSaysHowManyURLsWerePaired(t *testing.T) {
	srv, _ := identityApp(t)
	db := filepath.Join(t.TempDir(), "ws.db")
	for range 2 {
		fetch.Reset()
		fetch.SetProbeToken(fetch.RandomName())
		args := []string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-catchall-after", "0", "-quiet", "-db", db}
		if _, errOut, err := captureBoth(t, func() error { return cmdRun(args) }); err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
	}
	out, errOut, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if !strings.Contains(out, "(no new entities or observations)") || !strings.Contains(out, "= 1 URLs are in both runs with another number in their query") ||
		!strings.Contains(out, "added=0 removed=0 observations=0 changed=0") {
		t.Errorf("report:\n%s", out)
	}
}

// The order of the query names is a different spelling of one page for diff,
// and still a different request: what a link says is what is sent, and every
// spelling of it is asked as the docs say.
func TestQueryOrderIsAskedAsWrittenAndComparedAsOne(t *testing.T) {
	srv, asked := identityApp(t)
	diffOfTwoRuns(t, srv)
	seen := map[string]bool{}
	for _, u := range asked() {
		seen[u] = true
	}
	if !seen["/list.php?sort=name&order=asc"] || !seen["/list.php?order=asc&sort=name"] {
		t.Errorf("a spelling of the link was reordered or not asked: %v", seen)
	}
}
