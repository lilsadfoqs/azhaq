package paramcol

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// sizeWords is a word list of one name that matters and n that do not.
func sizeWords(real string, n int) []string {
	words := []string{real}
	for i := 0; i < n; i++ {
		words = append(words, fmt.Sprintf("field%d", i))
	}
	return words
}

// reqs runs the search on a server and returns what it found and how many
// requests the server saw.
func reqs(t *testing.T, h http.HandlerFunc, path string, words []string) (map[string]any, int64) {
	t.Helper()
	fetch.Reset()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}))
	defer srv.Close()
	c := New(srv.Client(), Options{Words: words, Chunk: 50, Rate: 10000, Threads: 1})
	got := runOn(t, c, srv.URL+path)
	why, _ := got["why"].(map[string]any)
	return why, n.Load()
}

// stableNames are the names the stable page reads, each adding its own
// number of rows.
var stableNames = []string{"q", "sort", "limit", "page", "lang", "cat", "min", "max"}

func stableSearch(w http.ResponseWriter, r *http.Request) {
	rows := 30
	for i, n := range stableNames {
		if r.URL.Query().Get(n) != "" {
			rows += 7 * (i + 1)
		}
	}
	fmt.Fprint(w, `{"status":"success","data":[`+strings.Repeat(`{"id":1,"name":"juice"},`, rows)+`{}]}`)
}

// A stable search page (a JSON list, as Juice Shop's) with eight names
// that change its size: the first is asked again with fresh values, and
// the page stays calm, so the others are not. The count is that of the
// search with no repeats at all, plus the four of that one name.
func TestStableSearchPageIsAskedAgainOnlyOnce(t *testing.T) {
	why, n := reqs(t, stableSearch, "/rest/products/search", append(slices.Clone(stableNames), sizeWords("x", 41)[1:]...))
	if len(why) != len(stableNames) {
		t.Fatalf("found %v, want the %d names", why, len(stableNames))
	}
	t.Logf("stable page, %d names: %d requests", len(stableNames), n)
	if n > stableSearchMax {
		t.Errorf("%d requests on a stable page, want at most %d", n, stableSearchMax)
	}
}

// stableSearchMax is set from a run with sizeRepeats = 0 (the requests of
// the calibration, the groups, the confirmations and the controls), plus
// the 4 of one name's repeats.
const stableSearchMax = 78

// A page whose size wanders at random from the first request: the repeats
// are asked, and only the parameter that adds to the page is found.
func TestJitteryPageStillGetsSizeRepeats(t *testing.T) {
	var mu sync.Mutex
	rng := rand.New(rand.NewSource(11))
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		wobble := 40 * rng.Intn(3)
		mu.Unlock()
		body := "<html><body>profile" + strings.Repeat(".", wobble)
		if r.URL.Query().Get("limit") != "" {
			body += strings.Repeat(" <li>row</li>", 40)
		}
		fmt.Fprint(w, body+"</body></html>")
	}
	why, n := reqs(t, h, "/profile", sizeWords("limit", 49))
	t.Logf("jitter page: %d requests, found %v", n, why)
	if len(why) != 1 || why["limit"] != "size" {
		t.Fatalf("found %v, want limit alone", why)
	}
}

// The 404 page of #481: two big answers in a row every period requests,
// at every phase. No size-only name is listed, and the page's variation
// shows in the search before a name is believed.
func TestSteppingPageAtEveryPhaseListsNoSizeName(t *testing.T) {
	total := int64(0)
	runs := 0
	for _, period := range []int{6, 7, 9} {
		for phase := 0; phase < period; phase++ {
			var mu sync.Mutex
			k := 0
			h := func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				k++
				big := k > 3 && (k+phase)%period < 2
				mu.Unlock()
				w.WriteHeader(http.StatusNotFound)
				body := "<html><body>Not found "
				if big {
					body += strings.Repeat(".", 90)
				}
				if v := r.URL.Query().Get("q"); v != "" {
					body += " you searched " + v
				}
				fmt.Fprint(w, body+"</body></html>")
			}
			why, n := reqs(t, h, "/search/", append([]string{"q", "max"}, sizeWords("x", 47)[1:]...))
			total += n
			runs++
			if len(why) != 1 || why["q"] != "reflected" {
				t.Errorf("period %d phase %d: found %v, want q alone", period, phase, why)
			}
		}
	}
	t.Logf("stepping page: %d runs, %.1f requests on average", runs, float64(total)/float64(runs))
}

// A page that is calm while its first name is checked and starts to
// wander after it: the names that follow are asked again, as the page
// has shown it varies.
func TestPageThatStartsToWanderIsAskedAgain(t *testing.T) {
	var mu sync.Mutex
	rng := rand.New(rand.NewSource(5))
	n := 0
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		wobble := 0
		if n > 40 {
			wobble = 3 * rng.Intn(3)
		}
		mu.Unlock()
		rows := 30 + wobble
		for i, name := range stableNames {
			if r.URL.Query().Get(name) != "" {
				rows += 40 * (i + 1)
			}
		}
		fmt.Fprint(w, `{"data":[`+strings.Repeat(`{"id":1,"name":"juice"},`, rows)+`{}]}`)
	}
	why, got := reqs(t, h, "/rest/products/search", append(slices.Clone(stableNames), sizeWords("x", 41)[1:]...))
	t.Logf("wandering page: %d requests, found %v", got, why)
	if got <= stableSearchMax {
		t.Errorf("%d requests, want more than the stable page's %d", got, stableSearchMax)
	}
	for k := range why {
		if !slices.Contains(stableNames, k) {
			t.Errorf("%s is no name of the page", k)
		}
	}
}
