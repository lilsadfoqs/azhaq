package main

import (
	"fmt"
	"strings"
	"testing"
)

// A chain of four pages, the last loading an app script and a library; a
// fifth page is linked from the last.
func lastLevelSite(t *testing.T) *askedSite {
	t.Helper()
	return newAskedSite(t, map[string]string{
		"/":                                `<a href="/a">a</a>`,
		"/a":                               `<a href="/a/b">b</a>`,
		"/a/b":                             `<a href="/a/b/c">c</a>`,
		"/a/b/c":                           `<a href="/a/b/c/d">d</a><script src="/static/app.js"></script><script src="/static/react-dom.development.js"></script>`,
		"/a/b/c/d":                         `<script src="/static/fifth.js"></script>`,
		"/static/app.js":                   `fetch("/api/hidden");`,
		"/static/react-dom.development.js": `fetch("/lib/only");`,
		"/static/fifth.js":                 `fetch("/api/fifth");`,
	}, nil)
}

// A script a page loads is part of the page: the scripts of a page at the
// last level are requested and read, as those of any other page, and only
// the links to further pages count against -d.
func TestCrawlRequestsTheScriptsOfAPageAtTheLastLevel(t *testing.T) {
	srv := lastLevelSite(t)
	out, errOut := crawlOut(t, srv.Server, "-d", "3", "-json", "-hints")
	got := srv.asked()
	for _, p := range []string{"/static/app.js", "/static/react-dom.development.js"} {
		if !got[p] {
			t.Errorf("%s, loaded by the page at the last level, was not requested: %v", p, got)
		}
	}
	if got["/a/b/c/d"] || got["/static/fifth.js"] {
		t.Errorf("a page past -d 3, or its script, was requested: %v", got)
	}
	rows := urlRows(t, out)
	for _, p := range []string{"/static/app.js", "/static/react-dom.development.js"} {
		if r := rows[srv.URL+p]; r == nil || r["class"] != "observed" {
			t.Errorf("%s is not an observed row: %v", p, r)
		}
	}
	hidden := rows[srv.URL+"/api/hidden"]
	if hidden == nil || !strings.Contains(fmt.Sprint(hidden["found_in"]), "/static/app.js") {
		t.Errorf("/api/hidden is not listed as found in app.js: %v", hidden)
	}
	if rows[srv.URL+"/lib/only"] != nil || got["/lib/only"] {
		t.Error("a library script was read for routes")
	}
	if r := rows[srv.URL+"/a/b/c/d"]; r == nil || r["class"] != "linked" {
		t.Errorf("the page past -d is not a linked row: %v", r)
	}
	if !strings.Contains(errOut, `"scripts":2`) {
		t.Errorf("the summary does not count the two script requests:\n%s", errOut)
	}
}

// -max-scripts keeps its meaning for the scripts of a last-level page: the
// library the cap leaves out is not requested.
func TestCrawlMaxScriptsStillLimitsTheScriptsOfAPage(t *testing.T) {
	srv := lastLevelSite(t)
	crawlOut(t, srv.Server, "-d", "3", "-max-scripts", "1")
	got := srv.asked()
	if !got["/static/app.js"] || got["/static/react-dom.development.js"] {
		t.Errorf("-max-scripts 1 asked %v", got)
	}
}
