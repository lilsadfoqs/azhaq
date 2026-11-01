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
