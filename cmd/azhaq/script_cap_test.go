package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// manyScripts serves a page of n scripts and counts the script requests.
func manyScripts(t *testing.T, n int) (url string, scripts func() int) {
	t.Helper()
	var mu sync.Mutex
	got := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			var b strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, `<script src="/c%d.js"></script>`, i)
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><title>Big</title>%s</html>", b.String())
		case strings.HasPrefix(r.URL.Path, "/c") && strings.HasSuffix(r.URL.Path, ".js"):
			mu.Lock()
			got++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `fetch("/api/r%s");`, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/c"), ".js"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/", func() int { mu.Lock(); defer mu.Unlock(); return got }
}

// A page with more scripts than a pass reads leaves some unread: a note
// says how many, the run is complete as with -depth, and -fail-on-capped
// makes it exit 4 with the cap and what it left in the summary.
func TestScriptCapLeavesUnreadWorkNamedAndFailOnCapped(t *testing.T) {
	url, scripts := manyScripts(t, 300)
	base := []string{"run", "-url", url, "-sources", "none", "-no-paths", "-no-map-guess", "-allow", "127.0.0.1", "-max-requests", "2000"}
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, append(base, "-db", "a.db")...)
	if code != exitOK || !rep.Complete || rep.Stopped != "" {
		t.Errorf("without -fail-on-capped: exit %d complete %v stopped %q", code, rep.Complete, rep.Stopped)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "44 scripts (limit 256)") {
		t.Errorf("the notes do not say 44 scripts were left at 256: %v", rep.Notes)
	}
	if n := scripts(); n != 256 {
		t.Errorf("%d scripts read, want 256", n)
	}
	_, rep, code = runContract(t, append(base, "-db", "b.db", "-fail-on-capped")...)
	if code != exitLimit || rep.Complete {
		t.Errorf("-fail-on-capped: exit %d complete %v, want exit %d incomplete", code, rep.Complete, exitLimit)
	}
	if !strings.Contains(rep.Stopped, "-max-scripts 256") || !strings.Contains(rep.Stopped, "44 scripts (limit 256)") {
		t.Errorf("stopped does not name the cap and what it left: %q", rep.Stopped)
	}
}

// -max-scripts lifts the cap: every script is read and nothing is left.
func TestMaxScriptsReadsEveryScript(t *testing.T) {
	url, scripts := manyScripts(t, 300)
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-url", url, "-sources", "none", "-no-paths", "-no-map-guess", "-allow", "127.0.0.1",
		"-max-requests", "2000", "-max-scripts", "300", "-fail-on-capped", "-db", "c.db")
	if code != exitOK || !rep.Complete || rep.Stopped != "" {
		t.Errorf("exit %d complete %v stopped %q", code, rep.Complete, rep.Stopped)
	}
	if n := scripts(); n != 300 {
		t.Errorf("%d scripts read, want 300", n)
	}
	if strings.Contains(strings.Join(rep.Notes, "\n"), "left unread") {
		t.Errorf("a note says work was left: %v", rep.Notes)
	}
}

func TestMaxScriptsNegativeIsAUsageError(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, _, code := cli(t, "run", "-url", "http://127.0.0.1:1/", "-max-scripts", "-3"); code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}
