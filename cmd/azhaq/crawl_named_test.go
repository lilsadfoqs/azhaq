package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A route a script names on a page is a line of the crawl when the crawl
// asked for it: at -d 1 it is only named and needs -hints, at -d 2 it is
// requested. Whatever the list left out is counted in the summary, with
// -silent and -json too.
func TestCrawlListsAScriptsRouteOnlyWhenItWasAsked(t *testing.T) {
	pages := map[string]string{
		"/":        `<a href="/catalog">Catalog</a>`,
		"/catalog": `<script>var cats={"All":"/catalog","Gin":"/catalog?category=Gin","Juice":"/catalog?category=Juice"};</script>`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()
	lines := func(out string) []string { return strings.Fields(out) }
	gin := srv.URL + "/catalog?category=Gin"

	out, errOut := crawlOut(t, srv, "-d", "1", "-jc", "-jsl")
	if len(lines(out)) != 2 || strings.Contains(out, "category=") {
		t.Errorf("-d 1 lists %v", lines(out))
	}
	if !strings.Contains(errOut, "0 hints and 2 named URLs were left out of the list (-hints lists them; a larger -depth requests more of the named URLs") {
		t.Errorf("the summary does not say what was left out:\n%s", errOut)
	}
	if out, _ := crawlOut(t, srv, "-d", "1", "-jc", "-jsl", "-hints"); len(lines(out)) != 4 || !strings.Contains(out, gin) {
		t.Errorf("-d 1 -hints lists %v", lines(out))
	}
	if out, _ := crawlOut(t, srv, "-d", "2", "-jc", "-jsl"); len(lines(out)) != 4 || !strings.Contains(out, gin) {
		t.Errorf("-d 2 lists %v", lines(out))
	}
	// -silent prints no summary, and still says what the list left out.
	out, errOut = crawlOut(t, srv, "-d", "1", "-jc", "-jsl", "-silent")
	if len(lines(out)) != 2 || !strings.Contains(errOut, "azhaq crawl: 0 hints and 2 named URLs were left out of the list") {
		t.Errorf("-silent: stdout %v, stderr %q", lines(out), errOut)
	}
	_, errOut = crawlOut(t, srv, "-d", "1", "-jc", "-jsl", "-json")
	if !strings.Contains(errOut, `"named strings":2`) || !strings.Contains(errOut, "2 named URLs were left out of the list") {
		t.Errorf("-json summary: %s", errOut)
	}
}
