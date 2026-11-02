package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The JSON summary of run says how many stored rows folded into a printed
// row, so results + folded + left_out = stored can be read from it: with
// templated URLs, with a catch-all origin and -no-catchall, and with
// nothing to fold (folded is then 0, and present).
func TestRunSummaryCarriesFolded(t *testing.T) {
	check := func(t *testing.T, errOut string, wantFolded float64, wantLeft float64) {
		t.Helper()
		sum := sumMap(t, errOut)
		num := func(k string) float64 { f, _ := sum[k].(float64); return f }
		folded, ok := sum["folded"].(float64)
		if !ok {
			t.Fatalf("the summary has no folded: %v", sum)
		}
		if num("results")+folded+num("left_out") != num("stored") {
			t.Errorf("results %v + folded %v + left_out %v != stored %v", num("results"), folded, num("left_out"), num("stored"))
		}
		if folded != wantFolded || num("left_out") != wantLeft {
			t.Errorf("folded %v (want %v), left_out %v (want %v)", folded, wantFolded, num("left_out"), wantLeft)
		}
	}
	runArgs := func(srv *httptest.Server, extra ...string) string {
		args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon",
			"-json", "-quiet", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
		_, errOut, _ := captureBoth(t, func() error { return cmdRun(args) })
		return errOut
	}

	t.Run("templated rows", func(t *testing.T) {
		var links strings.Builder
		for i := 1; i <= 40; i++ {
			fmt.Fprintf(&links, `<a href="/item/%d">i</a>`, i)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><title>x</title>%s</html>`, links.String())
				return
			}
			if strings.HasPrefix(r.URL.Path, "/item/") {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><title>item</title></html>`)
				return
			}
			http.NotFound(w, r)
		}))
		t.Cleanup(srv.Close)
		errOut := runArgs(srv)
		sum := sumMap(t, errOut)
		if f, _ := sum["folded"].(float64); f < 30 {
			t.Fatalf("40 item pages fold into few rows: %v", sum)
		}
		check(t, errOut, sum["folded"].(float64), 0)
	})

	t.Run("no-catchall", func(t *testing.T) {
		srv, _ := shellApp(t, 4)
		errOut := runArgs(srv, "-catchall-after", "0", "-no-catchall")
		sum := sumMap(t, errOut)
		check(t, errOut, sum["folded"].(float64), 24)
	})

	t.Run("nothing folds", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>x</title></html>`)
		}))
		t.Cleanup(srv.Close)
		check(t, runArgs(srv), 0, 0)
	})
}
