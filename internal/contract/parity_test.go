package contract

import (
	"strings"
	"testing"
)

// What the reference crawler does with a page, written as what azhaq's
// default crawl must do: the stylesheets a page loads are requested and
// listed (katana does), and the keys of a webpack module map are no routes.

func listedURLs(t *testing.T, r Result) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, row := range r.Rows(t) {
		for _, k := range []string{"url", "key"} {
			if u, _ := row[k].(string); u != "" {
				out[u] = true
			}
		}
	}
	return out
}

func TestCrawlRequestsTheStylesheetsAPageLoads(t *testing.T) {
	l := newLabs(t)
	r := l.Cmd("crawl", "-u", l.Site.URL, "-d", "2")
	v := newInv(t, "#76")
	css := l.Site.URL + "/static/site.css"
	if !listedURLs(t, r)[css] {
		v.Errorf("the stylesheet the front page loads is not in the default list")
	}
	if l.Site.Wire.HTTP()["GET "+css] == 0 {
		v.Errorf("the stylesheet the front page loads was not requested")
	}
	if l.Site.Wire.HTTP()["GET "+l.Site.URL+"/static/logo.png"] != 0 {
		v.Errorf("an image was requested: images, fonts and media stay unrequested")
	}
	v.Done()
}

func TestCrawlTakesNoModuleMapKeyForARoute(t *testing.T) {
	site := webpackSite(t)
	dir := t.TempDir()
	r := Run(t, dir, "crawl", "-u", site.URL, "-d", "3", "-hints", "-json")
	v := newInv(t, "#93")
	for k := range site.Wire.HTTP() {
		for _, id := range []string{"/components/locale/", "/AdhocFilter", "/AdhocMetric"} {
			if strings.Contains(k, id) {
				v.Errorf("a module id was requested as a page: %s", k)
			}
		}
	}
	for u := range listedURLs(t, r) {
		if strings.Contains(u, "/components/locale/") || strings.HasSuffix(u, "/AdhocFilter") {
			v.Errorf("a module id is listed as a route: %s", u)
		}
	}
	if site.Wire.HTTP()["GET "+site.URL+"/api/v1/dashboards"] == 0 {
		v.Errorf("the route the bundle really calls was not requested")
	}
	v.Done()
}
