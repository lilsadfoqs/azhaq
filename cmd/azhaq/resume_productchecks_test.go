package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
)

// siteBehindProductChecks is a small site whose root sweep (path checks plus
// the product checks, over a thousand words) is far larger than the budget
// the test gives a process. Its map is the linked pages and the path checks
// that answer (/admin, /login, /api, /rest, /docs).
func siteBehindProductChecks(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch p := r.URL.Path; p {
		case "/":
			fmt.Fprint(w, `<html><title>Shop</title><a href="/a.html">a</a><a href="/b.html">b</a></body></html>`)
		case "/a.html", "/b.html":
			fmt.Fprintf(w, `<html><title>%s</title></html>`, p)
		case "/admin", "/login", "/api", "/rest", "/docs":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><title>%s</title><a href="%s/more">more</a></html>`, p, p)
		case "/admin/more", "/login/more":
			fmt.Fprint(w, `<html><title>more</title></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func mappedURLs(t *testing.T, db string) []string {
	t.Helper()
	out, _, _ := runContract(t, "query", "-db", db, "-type", "URL", "-fields", "key")
	var keys []string
	for _, l := range lines(out) {
		keys = append(keys, l)
	}
	sort.Strings(keys)
	return keys
}

// A run stopped by -max-requests and resumed with the same budget, where the
// sweep of the root needs many times that budget (its product checks), still
// ends having mapped what one run maps, and sends about what one run sends:
// a resume that makes progress is not told "no task finished".
func TestResumedRunWithASweepLargerThanTheBudgetMapsWhatOneRunMaps(t *testing.T) {
	srv, got := siteBehindProductChecks(t)
	t.Chdir(t.TempDir())
	if _, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-db", "one.db"); code != exitOK {
		t.Fatalf("one run: exit %d, stopped %q", code, rep.Stopped)
	}
	one := got.Load()
	words := len(pathscol.DefaultWordlist) + len(pathscol.ProductWords())
	const budget = 100
	if one < 5*budget || words < 5*budget {
		t.Fatalf("the sweep is too small to cut: one run sent %d, sweep has %d words", one, words)
	}
	want := mappedURLs(t, "one.db")

	got.Store(0)
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-db", "cut.db", "-max-requests", fmt.Sprint(budget))
	if code != exitLimit {
		t.Fatalf("the cut run: exit %d, stopped %q", code, rep.Stopped)
	}
	processes := 1
	for code == exitLimit && processes < 60 {
		_, rep, code = runContract(t, "resume", "-db", "cut.db", "-max-requests", fmt.Sprint(budget))
		processes++
		if note := strings.Join(rep.Notes, "\n"); strings.Contains(note, "no task finished") {
			t.Fatalf("process %d: %q, though %d requests of the sweep were still to ask (one run sent %d, %d so far)", processes, note, int(one)-int(got.Load()), one, got.Load())
		}
	}
	if code != exitOK {
		t.Fatalf("resume did not finish after %d processes: exit %d, stopped %q", processes, code, rep.Stopped)
	}
	have := mappedURLs(t, "cut.db")
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Errorf("the resumed run maps %v, one run %v", have, want)
	}
	t.Logf("%d processes; one run %d requests, cut and resumed %d", processes, one, got.Load())
	if all := got.Load(); float64(all) > 1.1*float64(one) {
		t.Errorf("a stopped and resumed run sent %d requests, one run %d (more than 10%% over)", all, one)
	}
}
