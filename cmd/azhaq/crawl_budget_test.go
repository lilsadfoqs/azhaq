package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// A site of many pages that link to each other and have buttons to click;
// seen is called on every request.
func manyPagesServer(seen func()) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen()
		n := 0
		if rest, ok := strings.CutPrefix(r.URL.Path, "/p/"); ok {
			n, _ = strconv.Atoi(rest)
		}
		var b strings.Builder
		for i := 1; i <= 12; i++ {
			fmt.Fprintf(&b, `<a href="/p/%d">page %d</a> `, (n*7+i)%400+1, i)
		}
		fmt.Fprintf(&b, `<button onclick="fetch('/api/n/%d')">load</button><button onclick="location.href='/p/%d'">go</button>`, n, n+1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><title>p%d</title><body>%s</body></html>`, n, b.String())
	}))
}

// The budget is spent: the run ends at once, with exit 4 and its work left
// for resume, however many pages Chrome still has open.
func TestBrowserCrawlEndsWhenTheBudgetIsSpent(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	// Timed from the request that spends the budget, not from the start:
	// Chrome's first launch on a runner takes seconds of its own.
	const budget = 25
	var hits atomic.Int32
	spent := make(chan struct{})
	srv := manyPagesServer(func() {
		if hits.Add(1) == budget {
			close(spent)
		}
	})
	defer srv.Close()
	t.Chdir(t.TempDir())
	type result struct {
		errOut string
		code   int
	}
	done := make(chan result, 1)
	go func() {
		_, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "2", "-browser", "-interact", "-interact-clicks", "30",
			"-no-map-guess", "-max-requests", strconv.Itoa(budget), "-db", "c.db", "-allow", "127.0.0.1")
		done <- result{errOut, code}
	}()
	var r result
	select {
	case r = <-done:
	case <-spent:
		select {
		case r = <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("the crawl was still running 10 s after its budget of %d requests was spent", budget)
			r = <-done // the run is in this process: the next test must not start beside it
		}
	case <-time.After(2 * time.Minute):
		t.Fatalf("the crawl neither ended nor spent its budget of %d requests in 2 minutes", budget)
	}
	if r.code != exitLimit {
		t.Errorf("exit %d, want %d (stopped by the budget)\n%s", r.code, exitLimit, r.errOut)
	}
}
