package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// export -run writes an earlier run of a workspace, as query -run reads it;
// without -run the newest run is written.
func TestExportReadsAnEarlierRun(t *testing.T) {
	site := func(name string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><title>%s</title>", name)
		}))
		t.Cleanup(s.Close)
		return s
	}
	one, two := site("one"), site("two")
	t.Chdir(t.TempDir())
	_, r1, code := runContract(t, "run", "-url", one.URL+"/", "-sources", "none", "-no-paths", "-db", "w.db")
	if code != exitOK {
		t.Fatalf("first run exit %d: %+v", code, r1.Failed)
	}
	_, r2, code := runContract(t, "run", "-url", two.URL+"/", "-sources", "none", "-no-paths", "-db", "w.db")
	if code != exitOK {
		t.Fatalf("second run exit %d: %+v", code, r2.Failed)
	}
	export := func(args ...string) (string, error) {
		out, _, err := runToFile(t, append([]string{"export", "-db", "w.db"}, args...)...)
		return out, err
	}
	for _, format := range []string{"urls", "graphml", "html"} {
		out, err := export("-format", format, "-run", r1.RunID[:8])
		if err != nil || !strings.Contains(out, one.URL) || strings.Contains(out, two.URL) {
			t.Errorf("-format %s -run %s: %v\n%.300s", format, r1.RunID[:8], err, out)
		}
		out, err = export("-format", format)
		if err != nil || !strings.Contains(out, two.URL) || strings.Contains(out, one.URL) {
			t.Errorf("-format %s: the newest run: %v\n%.300s", format, err, out)
		}
	}
	out, err := export("-run", r1.RunID)
	if err != nil || !strings.Contains(out, one.URL) || strings.Contains(out, two.URL) {
		t.Errorf("jsonl -run: %v\n%.300s", err, out)
	}
	if out, err = export(); err != nil || !strings.Contains(out, one.URL) || !strings.Contains(out, two.URL) {
		t.Errorf("jsonl without -run writes every run: %v\n%.300s", err, out)
	}
	for _, format := range []string{"urls", "jsonl"} {
		_, err = export("-format", format, "-run", "nosuchrun")
		if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "no such run in the workspace") {
			t.Errorf("-format %s: an unknown run is a usage error: %v", format, err)
		}
	}
}
