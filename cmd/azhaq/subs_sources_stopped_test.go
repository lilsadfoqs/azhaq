package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A stub source API on loopback: /fast answers at once, /slow holds the
// request until the test ends.
func sourceStub(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-done:
			case <-r.Context().Done():
			}
		}
	}))
	t.Cleanup(func() { close(done); srv.Close() })
	return srv
}

// A subs stopped while a source is still answering counts every source whose
// requests are in the ledger: asked (with the requests it made, as many as the
// ledger holds), answered, failed, and still running when the run stopped; it
// never says a source was not asked.
func TestSubsStoppedMidSourceCountsTheSourcesItAsked(t *testing.T) {
	stub := sourceStub(t)
	defer subcol.UseTestSources(
		subcol.TestSource{Name: "fast", Default: true, URL: stub.URL + "/fast", Names: []string{"a.example.org"}},
		subcol.TestSource{Name: "broken", Default: true, URL: stub.URL + "/fast", Names: []string{"b.example.org"}, Err: http.ErrAbortHandler},
		subcol.TestSource{Name: "slow", Default: true, URL: stub.URL + "/slow", Names: []string{"c.example.org"}},
	)()
	for _, stop := range [][]string{{"-timeout", "3s"}, {"-max-time", "2s"}} {
		t.Run(stop[0], func(t *testing.T) {
			t.Chdir(t.TempDir())
			args := append([]string{"subs", "-d", "example.org", "-no-history", "-ledger", "l.jsonl"}, stop...)
			t0 := time.Now()
			_, rep, code := runContract(t, args...)
			if took := time.Since(t0); took > 8*time.Second {
				t.Errorf("the run took %s", took)
			}
			if code != exitLimit {
				t.Fatalf("exit %d, stopped %q", code, rep.Stopped)
			}
			inLedger := 0
			if err := ledger.Read("l.jsonl", func(e ledger.Entry) error {
				if e.Class == "source" && e.Kind == "http" {
					inLedger++
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			c := rep.Counts
			if inLedger != 3 || c["sources asked"] != 3 || c["sources answered"] != 1 || c["sources failed"] != 1 || c["sources still running"] != 1 {
				t.Errorf("%d source requests in the ledger; counts %v", inLedger, c)
			}
			if c["sources asked"] != c["sources answered"]+c["sources failed"]+c["sources still running"] {
				t.Errorf("asked is not answered + failed + still running: %v", c)
			}
			h := rep.Sources
			if h == nil || h.Asked != 3 || h.Answered != 1 || h.Failed != 1 || h.Running != 1 {
				t.Fatalf("the sources block: %+v", h)
			}
			made := 0
			for _, n := range h.Requests {
				made += n
			}
			if made != inLedger || h.Requests["slow"] != 1 {
				t.Errorf("sources made %v requests, the ledger holds %d", h.Requests, inLedger)
			}
			if _, failed := h.FailedSources["slow"]; failed || h.FailedSources["broken"] == "" {
				t.Errorf("a source the stop caught asking is not a failed one: %v", h.FailedSources)
			}
			if line := h.line(code, false); !strings.Contains(line, "1 of 3 sources answered, 1 failed (listed above), 1 still running when the run stopped") {
				t.Errorf("the summary line: %s", line)
			}
		})
	}
}
