package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// chainSite is a page /chain/N for N below 12, each linking /chain/N+1 and
// /chain/N/x: a templated route whose members run past any -depth.
func chainSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		if rest, ok := strings.CutPrefix(r.URL.Path, "/chain/"); ok {
			n, _ = strconv.Atoi(strings.SplitN(rest, "/", 2)[0])
		}
		w.Header().Set("Content-Type", "text/html")
		if n > 0 && n < 12 {
			fmt.Fprintf(w, "<title>c%d</title><a href='/chain/%d'>n</a><a href='/chain/%d/x'>x</a>", n, n+1, n)
			return
		}
		fmt.Fprint(w, "end")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The depth note's URL count is the number of distinct capped URLs, and
// query -coverage capped returns every row that holds one, a templated row
// included.
func TestCappedURLsAreCountedOnceAndQueryFindsThem(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := chainSite(t)
	_, rep, _ := runContract(t, "run", "-url", srv.URL+"/chain/1", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover",
		"-no-paths", "-no-favicon", "-no-tech", "-depth", "2", "-db", "ch.db")
	var noted int
	for _, n := range rep.Notes {
		if m := depthNote.FindStringSubmatch(n); m != nil {
			noted, _ = strconv.Atoi(m[1])
		}
	}
	if noted == 0 {
		t.Fatalf("no depth note: %v", rep.Notes)
	}
	out, _, err := captureBoth(t, func() error {
		return run([]string{"query", "-db", "ch.db", "-coverage", "capped", "-json", "-type", "URL"})
	})
	if err != nil {
		t.Fatal(err)
	}
	urls := 0
	for _, l := range lines(out) {
		var row map[string]any
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatal(err)
		}
		if n, ok := row["capped"].(float64); ok {
			urls += int(n)
		} else if row["coverage"] == "capped" {
			urls++
		} else {
			t.Errorf("a row with no capped URL in it: %s", l)
		}
	}
	if urls != noted {
		t.Errorf("the note counts %d URLs, query -coverage capped holds %d:\n%s", noted, urls, out)
	}
}
