package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// One workspace, one count: the run's `next` hunt line, its summary tiers,
// `hunt` and `report -findings` agree on the findings, here the error
// disclosures a dirs pass found.
func TestRunNextLineCountsAgreeWithSummaryHuntAndReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api", "/rest", "/legacy": // /legacy shows its trace in a 200
			if r.URL.Path != "/legacy" {
				w.WriteHeader(500)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><head><title>Error: Unexpected path: %s</title></head><body><h1>Shop</h1><h2><em>500</em> Error: Unexpected path: %s</h2><ul id=\"stacktrace\"><li> &nbsp; &nbsp;at /app/build/routes/angular.js:38:18</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at next (/app/node_modules/express/lib/router/route.js:137:13)</li></ul></body></html>", r.URL.Path, r.URL.Path)
		default: // the SPA's index answers the rest
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>Acme</title><body><app-root></app-root><script src=\"/main.js\"></script></body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "n.db")
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-db", db, "-dirs", wlist(t, "api", "rest", "legacy", "nothing"),
		"-probe", "-params", wlist(t, "q", "id"), "-no-tech", "-no-paths", "-no-favicon", "-ledger", "off")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v", code, rep.Failed)
	}
	if rep.Tiers == nil || rep.Tiers.Findings != 3 {
		t.Fatalf("summary tiers %+v, want 3 findings (/api, /rest, /legacy)", rep.Tiers)
	}
	count := regexp.MustCompile(`\((\d+) findings?, (\d+) identifications?, (\d+) leads?\)`)
	var next []int
	for _, l := range rep.Next {
		if strings.HasPrefix(l, "azhaq hunt -db "+db) {
			if m := count.FindStringSubmatch(l); m != nil {
				for _, s := range m[1:] {
					n, _ := strconv.Atoi(s)
					next = append(next, n)
				}
			}
		}
	}
	if len(next) != 3 || next[0] != rep.Tiers.Findings || next[1] != rep.Tiers.Identifications || next[2] != rep.Tiers.Leads {
		t.Errorf("next line counts %v, summary tiers %+v: the findings must agree (%q)", next, rep.Tiers, rep.Next)
	}
	out, errOut, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	h := lastReport(t, errOut).Tiers
	if h == nil || h.Findings != rep.Tiers.Findings {
		t.Errorf("hunt tiers %+v (%s), run summary %+v", h, out, rep.Tiers)
	}
	rows := jsonLines(t, out)
	if len(rows) != 3 {
		t.Errorf("hunt lists %d rows, want the 3 findings and no lead repeating them:\n%s", len(rows), out)
	}
	for _, r := range rows {
		if r["tier"] != "finding" {
			t.Errorf("row %v is not a finding", r)
		}
	}
	_, errOut, err = captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl", "-o", filepath.Join(t.TempDir(), "f.jsonl")})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if want := fmt.Sprintf("report: %d findings", rep.Tiers.Findings); !strings.Contains(errOut, want) {
		t.Errorf("report -findings says %q, want %q", errOut, want)
	}
}
