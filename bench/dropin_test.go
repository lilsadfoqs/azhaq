package main

import "testing"

// The routes only the full map reaches are all in the truth (a misspelt
// one would quietly raise the bar), and what is left is what a crawler's
// check counts.
func TestCrawlTruthSplit(t *testing.T) {
	truth := readTruth("truth/juice-shop-v20.3.0-routes.txt")
	mapOnly := readTruth("truth/juice-shop-v20.3.0-full-map-only.txt")
	for r := range mapOnly {
		if !truth[r] {
			t.Errorf("%s is listed as reached only by the full map, and is no known route", r)
		}
	}
	rest, only := splitTruth(truth, mapOnly)
	if len(only) != len(mapOnly) || len(rest)+len(only) != len(truth) || len(rest) == 0 {
		t.Errorf("%d known routes split into %d and %d (map only: %d)", len(truth), len(rest), len(only), len(mapOnly))
	}
	for r := range only {
		if rest[r] {
			t.Errorf("%s is on both sides", r)
		}
	}
}

// The crawl comparison counts the stylesheets each tool lists: routes
// leaves them out, as it does every asset.
func TestStylesheetsAreCounted(t *testing.T) {
	urls := []string{"http://a.test/", "http://a.test/styles.css", "http://a.test/styles.css?v=2", "http://a.test/assets/app.CSS",
		"http://a.test/app.js", "http://b.test/other.css", "http://a.test/css/"}
	got := stylesheets(urls, "http://a.test")
	if len(got) != 2 || !got["/styles.css"] || !got["/assets/app.CSS"] {
		t.Errorf("stylesheets %v", got)
	}
	if r := routes(urls, "http://a.test"); r["/styles.css"] || !r["/css"] {
		t.Errorf("routes %v keeps an asset or loses a route", r)
	}
}
