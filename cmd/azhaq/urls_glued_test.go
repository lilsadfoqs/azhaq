package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const gluedURL = "http://example.org/admin/create.sqlA01http://example.org/artists.php"

// gluedWayback is a Wayback Machine whose only page holds a glued record,
// one glued to another host, a redirect-style path and a plain page.
func gluedWayback(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "0" {
			w.WriteHeader(http.StatusBadRequest) // past the last page
			return
		}
		fmt.Fprintf(w, `[["timestamp","original"],
["20190312083015",%q],
["20190312083016","http://example.org/index.php"],
["20190312083017","http://example.org/a.phpA01http://other.test/elsewhere"],
["20190312083018","http://example.org/go/http://other.test/ok"]]`, gluedURL)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// An archived URL with a second URL glued into its path is junk with its
// own reason and is never sent by -live; the URL it holds is listed on its
// own, under the same source, and is asked once, like any other row.
func TestURLsGluedURLIsJunkAndItsInnerURLIsListed(t *testing.T) {
	t.Chdir(t.TempDir())
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
	}))
	t.Cleanup(proxy.Close)
	args := []string{"urls", "-d", "example.org", "-json", "-sort", "-keep-junk", "-urls-pause", "0",
		"-live", "-live-rate", "50", "-live-proxy", proxy.URL, "-db", filepath.Join(t.TempDir(), "u.db"),
		"-providers", "wayback", "-archive", "wayback=" + gluedWayback(t)}
	out, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows := triageRows(t, out)
	g := rows[gluedURL]
	if g.Junk != "glued-url" || g.Reason != "another URL glued into the path or query" || g.Source != "wayback" || g.Verified != nil {
		t.Errorf("the glued row: %+v", g)
	}
	in := rows["http://example.org/artists.php"]
	if in.Junk != "" || in.Source != "wayback" || in.Archived != "2019-03-12T08:30:15Z" || in.Verified == nil || !*in.Verified {
		t.Errorf("the URL it holds: %+v", in)
	}
	if r := rows["http://example.org/a.phpA01http://other.test/elsewhere"]; r.Junk != "glued-url" {
		t.Errorf("a URL glued to another host's is junk too: %+v", r)
	}
	if r := rows["http://example.org/go/http://other.test/ok"]; r.Junk != "" {
		t.Errorf("a redirect-style path is not junk: %+v", r)
	}
	for u := range rows {
		if strings.HasPrefix(u, "http://other.test") {
			t.Errorf("a URL out of scope is listed: %s", u)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, u := range seen {
		if strings.Contains(u, "A01") {
			t.Errorf("a glued URL was sent: %s", u)
		}
	}
	if rep := lastReport(t, errOut); rep.Counts["dropped as junk"] != 2 {
		t.Errorf("counts %v", rep.Counts)
	}
}

// -raw gives the record as the archive gave it and lists nothing more.
func TestURLsRawDoesNotListTheGluedInnerURL(t *testing.T) {
	t.Chdir(t.TempDir())
	args := []string{"urls", "-d", "example.org", "-json", "-raw", "-urls-pause", "0",
		"-providers", "wayback", "-archive", "wayback=" + gluedWayback(t)}
	out, errOut, err := captureBoth(t, func() error { return run(args) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows := triageRows(t, out)
	if _, ok := rows[gluedURL]; !ok {
		t.Errorf("the record as given is missing: %v", rows)
	}
	if _, ok := rows["http://example.org/artists.php"]; ok {
		t.Errorf("-raw listed the URL glued into a record")
	}
}
