package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A page the crawl requested links two product pages. At -d 1 the crawl
// does not request them, so the default list does not hold them: -hints
// lists them, -json marks them linked, and the summary counts them apart.
func TestCrawlListsOnlyWhatItRequested(t *testing.T) {
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
	if strings.Contains(out, "productId=") || len(strings.Fields(out)) != 3 {
		t.Errorf("the default list holds links that were never requested:\n%s", out)
	}
	if !strings.Contains(errOut, "azhaq crawl: 2 URLs a page links were not requested") {
		t.Errorf("-silent does not say what the list left out: %q", errOut)
	}
	for _, args := range [][]string{{"-f", "url"}, {"-ot", "{{url}}"}, {"-jsonl"}} {
		if out, _ := crawlOut(t, srv, append([]string{"-d", "1"}, args...)...); strings.Contains(out, "productId=") {
			t.Errorf("%v lists a link that was never requested:\n%s", args, out)
		}
	}
	if out, _ := crawlOut(t, srv, "-d", "1", "-hints"); !strings.Contains(out, p17+"\n") || !strings.Contains(out, p18+"\n") {
		t.Errorf("-hints does not list the links:\n%s", out)
	}
	mu.Lock()
	for u := range asked {
		if strings.Contains(u, "productId=") {
			t.Errorf("the crawl requested %s", u)
		}
	}
	mu.Unlock()

	out, errOut = crawlOut(t, srv, "-d", "1", "-json", "-hints")
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
	counts, _ := sumMap(t, errOut)["counts"].(map[string]any)
	if counts["observed routes"] != float64(3) || counts["linked routes"] != float64(2) || counts["not requested"] != float64(2) {
		t.Errorf("counts: %v", counts)
	}
	out, errOut = crawlOut(t, srv, "-d", "1", "-json")
	if strings.Contains(out, "productId=") {
		t.Errorf("-json lists links that were never requested without -hints:\n%s", out)
	}
	if !strings.Contains(errOut, "2 URLs a page links were not requested") {
		t.Errorf("the -json summary does not say what the list left out: %s", errOut)
	}
	// At -d 2 the crawl requests them, and they are listed.
	if out, _ := crawlOut(t, srv, "-d", "2", "-silent"); !strings.Contains(out, p17+"\n") {
		t.Errorf("-d 2 does not list the requested pages:\n%s", out)
	}
}
