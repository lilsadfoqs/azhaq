package paramcol

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A page whose size wanders between three values from one request to the
// next, calm for the first three (the measures of calibration), is no
// evidence for a name that happens to land elsewhere twice: only the
// parameter that really adds to the page is found.
func TestSizeWithinThePagesOwnVarianceIsNoCandidate(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	rng := rand.New(rand.NewSource(7))
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		wobble := 0
		if n > 3 {
			wobble = 40 * rng.Intn(3)
		}
		mu.Unlock()
		body := "<html><body>profile" + strings.Repeat(".", wobble)
		if r.URL.Query().Get("limit") != "" {
			body += strings.Repeat(" <li>row</li>", 40)
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	defer srv.Close()
	words := []string{"limit"}
	for i := 0; i < 40; i++ {
		words = append(words, fmt.Sprintf("field%d", i))
	}
	c := New(srv.Client(), Options{Words: words, Chunk: 10, Rate: 10000, Threads: 1})
	got := runOn(t, c, srv.URL+"/profile")
	why, _ := got["why"].(map[string]any)
	if len(why) != 1 || why["limit"] != "size" {
		t.Fatalf("found %v, want limit alone", why)
	}
}

// A 404 page that shows two big answers in a row every six requests (a
// counter with a state) gave a name the same answer twice and calm answers
// to the four controls sent after it. A name asked again with another
// value, each time followed by a control, does not stand apart from it:
// only q, which the page prints, is found.
func TestSizeThatDoesNotRepeatIsNotListed(t *testing.T) {
	for _, period := range []int{6, 7, 9} {
		fetch.Reset()
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			big := n > 3 && n%period < 2
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
		}))
		words := []string{"q", "max"}
		for i := 0; i < 48; i++ {
			words = append(words, fmt.Sprintf("field%d", i))
		}
		c := New(srv.Client(), Options{Words: words, Chunk: 50, Rate: 10000, Threads: 1})
		got := runOn(t, c, srv.URL+"/search/")
		why, _ := got["why"].(map[string]any)
		if len(why) != 1 || why["q"] != "reflected" {
			t.Errorf("period %d: found %v, want q alone", period, why)
		}
		srv.Close()
	}
}
