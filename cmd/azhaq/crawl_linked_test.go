package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A page the crawl requested links two product pages. At -d 1 the crawl does
// not request them, but the page links them, so the default list holds them
// as katana's does: -json marks them linked, the summary counts them apart
// and a note says how many listed URLs were never requested.
func TestCrawlListsWhatPagesLink(t *testing.T) {
	pages := map[string]string{
		"/":        `<a href="/catalog">Catalog</a><a href="/about">About</a>`,
		"/about":   `about`,
		"/catalog": `<a href="/catalog/product?productId=17">17</a><a href="/catalog/product?productId=18">18</a>`,
	}
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.RequestURI()] = true
		mu.Unlock()
		b, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()
	p17, p18 := srv.URL+"/catalog/product?productId=17", srv.URL+"/catalog/product?productId=18"

	out, errOut := crawlOut(t, srv, "-d", "1", "-silent")
	if !strings.Contains(out, p17+"\n") || !strings.Contains(out, p18+"\n") || len(strings.Fields(out)) != 5 {
		t.Errorf("the default list does not hold the links of a page it read:\n%s", out)
	}
	if !strings.Contains(errOut, "azhaq crawl: 2 listed URLs are links or loads a page holds that the crawl did not request") {
		t.Errorf("-silent does not say how many listed URLs were not requested: %q", errOut)
	}
	for _, args := range [][]string{{"-f", "url"}, {"-ot", "{{url}}"}, {"-jsonl"}} {
		if out, _ := crawlOut(t, srv, append([]string{"-d", "1"}, args...)...); !strings.Contains(out, "productId=17") {
			t.Errorf("%v does not list a link of a page it read:\n%s", args, out)
		}
	}
	mu.Lock()
	for u := range asked {
		if strings.Contains(u, "productId=") {
			t.Errorf("the crawl requested %s", u)
		}
	}
	mu.Unlock()

	out, errOut = crawlOut(t, srv, "-d", "1", "-json")
	classes := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var row struct{ URL, Class string }
		if json.Unmarshal([]byte(l), &row) == nil && row.URL != "" {
			classes[row.URL] = row.Class
		}
	}
	if classes[p17] != "linked" || classes[p18] != "linked" || classes[srv.URL+"/catalog"] != "observed" {
		t.Errorf("-json classes: %v", classes)
	}
	sum := sumMap(t, errOut)
	counts, _ := sum["counts"].(map[string]any)
	if counts["observed routes"] != float64(3) || counts["linked routes"] != float64(2) || counts["not requested"] != float64(2) || counts["requested"] != float64(3) {
		t.Errorf("counts: %v", counts)
	}
	if counts["hint"] != float64(2) || counts["visited"] != float64(3) || sum["results"] != float64(5) {
		t.Errorf("the printed rows do not add up: %v, results %v", counts, sum["results"])
	}
	if !strings.Contains(errOut, "2 listed URLs are links or loads a page holds that the crawl did not request") {
		t.Errorf("the -json summary does not say how many listed URLs were not requested: %s", errOut)
	}
	// At -d 2 the crawl requests them: nothing is left to say.
	out, errOut = crawlOut(t, srv, "-d", "2", "-silent", "-all-rows") // the product pages answer 404: folded by default
	if !strings.Contains(out, p17+"\n") {
		t.Errorf("-d 2 does not list the requested pages:\n%s", out)
	}
	if strings.Contains(errOut, "were not requested") || strings.Contains(errOut, "did not request") {
		t.Errorf("-d 2 requested every link, and says it did not: %q", errOut)
	}
}

// A -deny-path rule keeps a link out of the requests, not out of the list:
// the row is listed, linked, and the note counts it.
func TestCrawlListsLinkOfDenyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<a href="/logout">out</a><a href="/home">home</a>`))
			return
		}
		_, _ = w.Write([]byte(`page`))
	}))
	defer srv.Close()
	out, errOut := crawlOut(t, srv, "-deny-path", "^/logout", "-silent", "-all-rows") // every path answers the one page: folded by default
	if !strings.Contains(out, srv.URL+"/logout\n") || !strings.Contains(out, srv.URL+"/home\n") {
		t.Errorf("the list lacks the link a rule kept out of the requests:\n%s", out)
	}
	if !strings.Contains(errOut, "1 listed URLs are links or loads a page holds that the crawl did not request") {
		t.Errorf("the note does not count it: %q", errOut)
	}
}
