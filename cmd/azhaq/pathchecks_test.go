package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// The plan lists the built-in path checks for each web service; the run's
// summary says, for each service, how many it sent and, when fewer, how many
// it skipped and why. A server that serves an API description needs fewer
// (the guesses of a description stop at the first found), and a plain one
// gets them all.
func TestRunSaysWhatBecameOfThePlannedPathChecks(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/users":{"get":{"responses":{"200":{"description":"ok"}}}}}}`)
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>api</title>")
		default:
			http.NotFound(w, r)
		}
	}))
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>plain</title>")
	}))
	t.Cleanup(api.Close)
	t.Cleanup(plain.Close)
	t.Chdir(t.TempDir())
	list := api.URL + "/\n" + plain.URL + "/\n"
	if err := os.WriteFile("hosts.txt", []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"-list", "hosts.txt", "-sources", "none"}
	p := planJSON(t, flags...)
	if len(p.Paths) == 0 {
		t.Fatal("the plan lists no built-in path checks")
	}
	_, rep, code := runContract(t, append(append([]string{"run"}, flags...), "-db", "w.db")...)
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	if rep.RequestsBy["path checks"] == 0 {
		t.Errorf("the plan lists %d path checks, the run sent none: %v", len(p.Paths), rep.RequestsBy)
	}

	// What the ledger holds for each service: the requests of the sweep.
	sentBy := map[string]int{}
	if err := ledger.Read("w.db.ledger.jsonl", func(e ledger.Entry) error {
		if e.Collector == "azhaq-paths" && (e.Purpose == ledger.PurposePathChecks || e.Purpose == ledger.PurposeDescriptions) {
			sentBy[e.Target[:strings.Index(e.Target[len("http://"):], "/")+len("http://")]]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	by := map[string]pathCheck{}
	for _, c := range rep.PathChecks {
		by[c.Service] = c
	}
	for _, srv := range []*httptest.Server{api, plain} {
		c, ok := by[srv.URL]
		if !ok || c.Sent == nil {
			t.Fatalf("no path checks for %s in the summary: %+v", srv.URL, rep.PathChecks)
		}
		if c.Listed != len(p.Paths) {
			t.Errorf("%s: %d listed, the plan lists %d", srv.URL, c.Listed, len(p.Paths))
		}
		if *c.Sent+c.Answered+c.Skipped != c.Listed {
			t.Errorf("%s: sent %d + already answered %d + skipped %d is not the %d listed", srv.URL, *c.Sent, c.Answered, c.Skipped, c.Listed)
		}
		if *c.Sent != sentBy[srv.URL] {
			t.Errorf("%s: the summary says %d sent, the ledger holds %d", srv.URL, *c.Sent, sentBy[srv.URL])
		}
	}
	if c := by[plain.URL]; c.Skipped != 0 || c.Reason != "" {
		t.Errorf("the plain server had every check sent: %+v", c)
	}
	if c := by[api.URL]; c.Skipped == 0 || !strings.Contains(c.Reason, "an API description was already found") {
		t.Errorf("the server with a description skipped none, or does not say why: %+v", c)
	}
}

// A check refused by a limit is a skip with that limit as its reason.
func TestPathChecksNameTheLimitThatRefusedThem(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>plain</title>")
	}))
	t.Cleanup(plain.Close)
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-url", plain.URL+"/", "-sources", "none", "-host-guesses", "10", "-db", "w.db")
	if code != exitLimit {
		t.Fatalf("exit %d, want %d: %+v", code, exitLimit, rep.Notes)
	}
	if len(rep.PathChecks) != 1 || rep.PathChecks[0].Sent == nil {
		t.Fatalf("path_checks: %+v", rep.PathChecks)
	}
	c := rep.PathChecks[0]
	if *c.Sent != 10 || c.Skipped == 0 || !strings.Contains(c.Reason, "-host-guesses reached for this host") {
		t.Errorf("a host cut at 10 guesses: %+v", c)
	}
}
