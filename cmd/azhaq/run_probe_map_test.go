package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -probe prints one line per web service; the rows a -dirs sweep found are
// URL rows of the map the summary counts, so they print too.
func TestRunProbePrintsTheRowsTheSummaryCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "<html><title>home</title></html>")
		case "/rest", "/assets":
			fmt.Fprintf(w, "<html><title>%s</title>found</html>", r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-probe", "-dirs", wlist(t, "rest", "assets", "nothere"), "-dirs-ac=false",
		"-dirs-mc", "all", "-no-paths", "-no-favicon", "-no-tech", "-depth", "0", "-allow", "127.0.0.1", "-stream", "-db", "p.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, p := range []string{"/rest", "/assets"} {
		if !strings.Contains(out, "found  url     "+srv.URL+p) {
			t.Fatalf("the stream lacks %s:\n%s", p, out)
		}
		if !strings.Contains(out, "\n"+srv.URL+p+" [") {
			t.Errorf("the printed map lacks %s, which the run found:\n%s\n%s", p, out, errOut)
		}
	}
}
