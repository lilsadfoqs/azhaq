package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A crawl stopped by -max-items does not say -depth stopped it, and a resume
// at the same cap that sends no request says so and goes on with the next.
func TestCrawlStoppedByMaxItemsDoesNotBlameDepth(t *testing.T) {
	t.Chdir(t.TempDir())
	defer fetch.SetProbeToken(fetch.ProbeToken())
	fetch.SetProbeToken("p3n0thodzmue")
	srv := pageSite(t, 6, 30)
	_, rep, code := runContract(t, "crawl", "-u", srv.URL+"/", "-db", "c.db", "-depth", "9", "-max-items", "10")
	if code != exitLimit || !strings.Contains(rep.Stopped, "-max-items 10 reached") {
		t.Fatalf("crawl: exit %d, stopped %q", code, rep.Stopped)
	}
	var quiet, said bool
	for i := 0; code != exitOK; i++ {
		if i == 40 {
			t.Fatalf("still stopped after %d resumes: %q", i, rep.Stopped)
		}
		_, rep, code = runContract(t, "resume", "-db", "c.db", "-max-items", "10")
		notes := strings.Join(rep.Notes, "\n")
		if strings.Contains(notes, "-depth 9") {
			t.Errorf("resume %d: -depth 9 is not what stopped it: %q", i, rep.Notes)
		}
		if code == exitLimit && rep.Requests == 0 {
			quiet = true
			if strings.Contains(notes, "sent no request") && strings.Contains(notes, "-max-items 10") {
				said = true
			}
		}
		if code == exitLimit && rep.Requests == 0 && !strings.Contains(notes, "sent no request") {
			t.Errorf("resume %d sent no request and its notes do not say so: %q", i, rep.Notes)
		}
	}
	if !quiet || !said {
		t.Errorf("a resume at the same cap that sent nothing: seen %v, said so %v", quiet, said)
	}
}

// A URL that answered 429 and answers 200 when -retry-failed asks it again is
// 200 in the map, in its status and its proof; the first run's note does not
// say azhaq waited when -backoff was off.
func TestRetryFailedShowsTheNewAnswerAndNoWaitNoteWithoutBackoff(t *testing.T) {
	var healed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, "<title>home</title><a href='/limited'>l</a>")
		case r.URL.Path == "/limited" && !healed.Load():
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "slow down")
		case r.URL.Path == "/limited":
			fmt.Fprint(w, "<title>limited page</title>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "e.db")
	flags := []string{"-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths", "-no-favicon", "-no-tech", "-db", db, "-ledger", "off", "-json"}
	out, errOut, err := captureBoth(t, func() error { return run(append([]string{"run", "-url", srv.URL + "/", "-backoff=false"}, flags...)) })
	first := lastReport(t, errOut)
	if exitCode(err) != exitOK || !strings.Contains(out, `"status":429`) {
		t.Fatalf("first run: exit %d, %v\n%s", exitCode(err), first.Notes, out)
	}
	notes := strings.Join(first.Notes, "\n")
	if strings.Contains(notes, "azhaq waited") || !strings.Contains(notes, "did not wait") {
		t.Errorf("-backoff=false, nothing waited: notes %q", first.Notes)
	}
	healed.Store(true)
	out, errOut, err = captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	if err != nil {
		t.Fatalf("resume -retry-failed: %v\n%s", err, errOut)
	}
	var row string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, `"key":"`+srv.URL+`/limited"`) {
			row = l
		}
	}
	// The status, not "429" anywhere: the server's port may hold those digits.
	if !strings.Contains(row, `"status":200`) || strings.Contains(row, `"status":429`) || !strings.Contains(row, `"proof":"status=200 title=limited page"`) {
		t.Errorf("the retried URL's row: %s", row)
	}
}

// With -backoff a host that answered 429 is waited for, and the note counts
// the waits.
func TestBackoffNoteCountsTheWaits(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && n.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "<title>home</title>")
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", srv.URL + "/", "-backoff", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover", "-no-paths", "-no-favicon", "-no-tech", "-depth", "0", "-db", "b.db", "-ledger", "off", "-json"})
	})
	rep := lastReport(t, errOut)
	notes := strings.Join(rep.Notes, "\n")
	if exitCode(err) != exitOK || !strings.Contains(notes, "azhaq waited 1 times") || strings.Contains(notes, "did not wait") {
		t.Errorf("exit %d, notes %q", exitCode(err), rep.Notes)
	}
}
