package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCanonicalFoldsOnlyWhatTheStandardSaysIsTheSame(t *testing.T) {
	same := [][]string{
		{"http://h.test/about", "HTTP://H.test/about", "http://h.test:80/about", "http://h.test/about#top", "http://h.test/%61bout", "http://h.test/%61bout#x"},
		{"https://h.test", "https://h.test/", "https://h.test:443/", "https://H.TEST"},
		{"http://h.test/a%2fb", "http://h.test/a%2Fb"},
		{"http://h.test/q?a=%7e", "http://h.test/q?a=~"},
	}
	for _, g := range same {
		for _, u := range g[1:] {
			if canonical(u) != canonical(g[0]) {
				t.Errorf("%s and %s are one resource: %s, %s", g[0], u, canonical(g[0]), canonical(u))
			}
		}
	}
	other := [][2]string{
		{"http://h.test/about", "http://h.test/about/"},
		{"http://h.test/about", "http://h.test/about?"},
		{"http://h.test/q?a=1&b=2", "http://h.test/q?b=2&a=1"},
		{"http://h.test/a/b", "http://h.test/a/./b"},
		{"http://h.test/a%2fb", "http://h.test/a/b"},
		{"http://h.test/About", "http://h.test/about"},
		{"http://h.test:8080/a", "http://h.test/a"},
		{"http://h.test/a", "https://h.test/a"},
	}
	for _, p := range other {
		if canonical(p[0]) == canonical(p[1]) {
			t.Errorf("%s and %s are two requests", p[0], p[1])
		}
	}
	// A URL as azhaq normalizes it is kept as it is.
	for _, u := range []string{"http://127.0.0.1:3001/rest/products/search?q=", "https://h.test/a/b?x=1&y=%2F", "http://h.test/", "http://h.test/{id}"} {
		if canonical(u) != u {
			t.Errorf("%s is changed to %s", u, canonical(u))
		}
	}
}

// A page already asked under another spelling is not sent again: its answer
// is the one kept, whichever way it is written; a spelling that is another
// request is sent.
func TestOnePageUnderManySpellingsIsAskedOnce(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.RequestURI()]++
		mu.Unlock()
		_, _ = w.Write([]byte("page " + r.URL.RequestURI()))
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	first := srv.URL + "/about"
	res, again, err := Do(context.Background(), srv.Client(), first)
	if err != nil || again {
		t.Fatalf("first ask: again=%v err=%v", again, err)
	}
	for _, alias := range []string{srv.URL + "/%61bout", srv.URL + "/about#top", "HTTP://" + host + "/about", srv.URL + "/%61bout#x"} {
		got, cached, err := Do(context.Background(), srv.Client(), alias)
		if err != nil || !cached {
			t.Errorf("%s: cached=%v err=%v, want the kept answer", alias, cached, err)
			continue
		}
		if string(got.Body) != string(res.Body) || got.RequestURL != alias {
			t.Errorf("%s: body %q request URL %q", alias, got.Body, got.RequestURL)
		}
	}
	for _, other := range []string{srv.URL + "/about/", srv.URL + "/about?", srv.URL + "/q?a=1&b=2", srv.URL + "/q?b=2&a=1"} {
		if _, cached, err := Do(context.Background(), srv.Client(), other); err != nil || cached {
			t.Errorf("%s: cached=%v err=%v, want a request of its own", other, cached, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/about"] != 1 || hits["/%61bout"] != 0 {
		t.Errorf("the server got %v: the page was asked for more than once", hits)
	}
	total := 0
	for _, n := range hits {
		total += n
	}
	if total != 5 {
		t.Errorf("the server got %d requests (%v), want 5: /about and the four that are other requests", total, hits)
	}
}
