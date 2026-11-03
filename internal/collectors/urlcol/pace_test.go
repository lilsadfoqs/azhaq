package urlcol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/types"
)

// archiveAnswers stands in for the archives with recorded shapes: a CDX
// answer for a filtered query where a page in the middle holds no row (the
// archive's own answer to "-mc 200 -ft image/png"), a urlscan search of
// 120 pages, and an OTX list. It records when each request came.
type archiveAnswers struct {
	*httptest.Server
	mu   sync.Mutex
	log  []asked
	cdx  map[int]string // page → body; a page that is not here is a 400
	scan int            // urlscan pages
}

type asked struct {
	path string
	page int
	at   time.Time
}

func newArchiveAnswers(t *testing.T, cdx map[int]string, scanPages int) *archiveAnswers {
	a := &archiveAnswers{cdx: cdx, scan: scanPages}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		page, _ := strconv.Atoi(q.Get("page"))
		after := q.Get("search_after")
		if after != "" {
			page, _ = strconv.Atoi(strings.Split(after, ",")[0])
		}
		a.mu.Lock()
		a.log = append(a.log, asked{r.URL.Path, page, time.Now()})
		a.mu.Unlock()
		switch r.URL.Path {
		case "/wayback":
			body, ok := a.cdx[page]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, body)
		case "/urlscan":
			next := page + 1
			res := fmt.Sprintf(`{"page":{"url":"http://example.org/scan/%d","status":"200"},"task":{"url":"http://example.org/t"},"sort":[%d,"x"]}`, next, next)
			fmt.Fprintf(w, `{"has_more":%t,"results":[%s]}`, next < a.scan, res)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *archiveAnswers) pagesOf(path string) (pages []int, at []time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.log {
		if x.path == path {
			pages, at = append(pages, x.page), append(at, x.at)
		}
	}
	return
}

// runDefault runs the collector as urls does with no pace flag given:
// New's own pauses, not the test helper's.
func runDefault(t *testing.T, o Options) (summary map[string]any, urls []string) {
	t.Helper()
	o.OnURL = func(u, _ string) { urls = append(urls, u) }
	c := New(o)
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(ob types.Observation) error {
		if ob.Kind == "urls" {
			_ = json.Unmarshal(ob.Payload, &summary)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

// The Wayback Machine is read in page order, request after request, as gau
// reads it: no wait between pages, and a page with no row is not the end.
func TestWaybackIsReadInOrderAtTheRateGauReadsIt(t *testing.T) {
	cdx := map[int]string{
		0: `[["timestamp","original"],["20240101000000","http://example.org/a"],["20240102000000","http://example.org/b"]]`,
		1: `[]`, // every capture of the page was filtered out
		2: `[["timestamp","original"]]`,
		3: `[["timestamp","original"],["20240301000000","http://example.org/late"]]`,
	}
	a := newArchiveAnswers(t, cdx, 0)
	start := time.Now()
	summary, urls := runDefault(t, Options{Client: a.Client(), Only: []string{"wayback"}, Bases: map[string]string{"wayback": a.URL + "/wayback"}})
	took := time.Since(start)
	pages, at := a.pagesOf("/wayback")
	if fmt.Sprint(pages) != "[0 1 2 3 4]" {
		t.Errorf("pages asked %v, want 0 to 4 in order (4 is past the last, a 400)", pages)
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap > 400*time.Millisecond {
			t.Errorf("page %d came %v after page %d: no wait belongs between pages", pages[i], gap, pages[i-1])
		}
	}
	if took > time.Second {
		t.Errorf("five pages took %v; at 1 s a request it is 4 s", took)
	}
	if fmt.Sprint(urls) != "[http://example.org/a http://example.org/b http://example.org/late]" {
		t.Errorf("urls %v: the URL after the empty pages is lost", urls)
	}
	if summary["count"].(float64) != 3 {
		t.Errorf("summary %v", summary)
	}
	if row := summary["sources"].(map[string]any)["wayback"].(map[string]any); row["error"] != nil || row["pages"].(float64) != 4 {
		t.Errorf("row %v", row)
	}
}

// A body with nothing in it is the end, as gau takes it.
func TestWaybackEmptyBodyEndsTheReading(t *testing.T) {
	a := newArchiveAnswers(t, map[int]string{0: `[["timestamp","original"],["20240101000000","http://example.org/a"]]`, 1: ``, 2: `[["timestamp","original"],["20240101000000","http://example.org/never"]]`}, 0)
	_, urls := runDefault(t, Options{Client: a.Client(), Only: []string{"wayback"}, Bases: map[string]string{"wayback": a.URL + "/wayback"}})
	if pages, _ := a.pagesOf("/wayback"); fmt.Sprint(pages) != "[0 1]" || fmt.Sprint(urls) != "[http://example.org/a]" {
		t.Errorf("pages %v urls %v", pages, urls)
	}
}

// urlscan.io answers up to 100 pages of 100; gau reads them all, with no
// wait and no cap, and so does urls unless -urls-pages is given.
func TestUrlscanIsReadToTheEndWithNoCapAndNoWait(t *testing.T) {
	a := newArchiveAnswers(t, nil, 120)
	start := time.Now()
	summary, urls := runDefault(t, Options{Client: a.Client(), Only: []string{"urlscan"}, Bases: map[string]string{"urlscan": a.URL + "/urlscan"}})
	took := time.Since(start)
	pages, _ := a.pagesOf("/urlscan")
	if len(pages) != 120 {
		t.Errorf("%d pages asked, want 120", len(pages))
	}
	if took > 3*time.Second {
		t.Errorf("120 pages took %v; at 2 s a page it is 4 minutes", took)
	}
	row := summary["sources"].(map[string]any)["urlscan"].(map[string]any)
	if row["capped"] != nil || len(urls) < 120 {
		t.Errorf("row %v, %d urls", row, len(urls))
	}
}
