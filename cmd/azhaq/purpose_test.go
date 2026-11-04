package main

import (
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// purposesOfLedger reads a ledger's lines to targets and groups them by the
// purpose each names.
func purposesOfLedger(t *testing.T, path string) (map[string]int, []ledger.Entry) {
	t.Helper()
	by := map[string]int{}
	var all []ledger.Entry
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if e.Kind != ledger.KindSeal && e.IsTarget() {
			by[e.Purpose]++
			all = append(all, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return by, all
}

// The summary says where the requests of a run went: by purpose, adding up to
// its requests, to the ledger's lines to targets and to what the server saw.
// Each line of the ledger names its purpose, and the purpose holds for it: a
// control is the request for a path that cannot exist, a script's path ends
// in a script's name, a description check is a place an API description is
// guessed at.
func TestRunSplitsItsRequestsByPurpose(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "w.db")
	sum := runJSON(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", db,
		"-dirs", wordsFile(t, 12), "-ports", portOfURL(srv.URL), "-port-detect", "none")
	by, ents := purposesOfLedger(t, db+".ledger.jsonl")
	got, _ := sum["requests_by_purpose"].(map[string]any)
	if len(got) == 0 {
		t.Fatalf("the summary does not split the requests by purpose: %v", sum)
	}
	total := 0
	for p, n := range got {
		total += int(n.(float64))
		if by[p] != int(n.(float64)) {
			t.Errorf("%s: the summary says %v, the ledger's lines say %d", p, n, by[p])
		}
	}
	for p, n := range by {
		if _, ok := got[p]; !ok {
			t.Errorf("%s: %d ledger lines, none in the summary", p, n)
		}
	}
	if want := int(sum["requests"].(float64)); total != want || len(ents) != want {
		t.Errorf("the purposes add up to %d, the summary says %d requests, the ledger has %d lines to targets", total, want, len(ents))
	}
	// The server saw each request but the connect to the open port.
	if int64(total-int(got["connections"].(float64))) != hits.Load() {
		t.Errorf("the purposes less the connections are %d, the server saw %d requests", total-int(got["connections"].(float64)), hits.Load())
	}
	for _, p := range []string{ledger.PurposePages, ledger.PurposeScripts, ledger.PurposeControls, ledger.PurposeDescriptions,
		ledger.PurposePathChecks, ledger.PurposeSweep, ledger.PurposeConnections} {
		if got[p] == nil {
			t.Errorf("no %q in %v", p, got)
		}
	}
	desc := []string{"swagger", "openapi", "api-docs", "graphql", "graphiql", "gql", "playground", "redoc", "docs", "api/schema", "api-json", "apispec", "documentation/json"}
	for _, e := range ents {
		u, _ := url.Parse(e.Target)
		switch e.Purpose {
		case ledger.PurposeControls:
			if !strings.HasSuffix(u.Path, fetch.ProbeToken()) {
				t.Errorf("a control that is not a path that cannot exist: %s", e.Target)
			}
		case ledger.PurposeScripts:
			if !strings.HasSuffix(u.Path, ".js") && !strings.HasSuffix(u.Path, ".css") && !strings.HasSuffix(u.Path, ".map") {
				t.Errorf("a script that is not one: %s", e.Target)
			}
		case ledger.PurposeDescriptions:
			ok := false
			for _, d := range desc {
				ok = ok || strings.Contains(u.Path, d)
			}
			if !ok {
				t.Errorf("a description check that names no description: %s", e.Target)
			}
		case ledger.PurposePages:
			if strings.HasSuffix(u.Path, ".js") || strings.HasSuffix(u.Path, ".css") || strings.HasSuffix(u.Path, fetch.ProbeToken()) {
				t.Errorf("a page that is a script or a control: %s", e.Target)
			}
		case "":
			t.Errorf("a line with no purpose: %s %s", e.Collector, e.Target)
		}
	}
}

// A crawl says the same, in its text summary too.
func TestCrawlSplitsItsRequestsByPurpose(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	out, errOut := crawlOut(t, srv, "-json")
	_ = out
	sum := sumMap(t, errOut)
	got, _ := sum["requests_by_purpose"].(map[string]any)
	total := 0
	for _, n := range got {
		total += int(n.(float64))
	}
	if total == 0 || total != int(sum["requests"].(float64)) || int64(total) != hits.Load() {
		t.Errorf("the purposes add up to %d, the summary says %v requests, the server saw %d: %v", total, sum["requests"], hits.Load(), got)
	}
	if got["pages"] == nil || got["scripts"] == nil {
		t.Errorf("a crawl of a page and its script: %v", got)
	}
	_, text := crawlOut(t, srv)
	if !strings.Contains(text, "requests by purpose: ") {
		t.Errorf("the text summary does not split the requests:\n%s", text)
	}
}
