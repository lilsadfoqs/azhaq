package dirscol

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
)

// orderedServer answers like foldServer and logs every path in the order it
// came.
func orderedServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		log = append(log, r.URL.Path)
		mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/api/users" || p == "/api/items":
			fmt.Fprint(w, `{"ok":true}`)
		case strings.HasPrefix(p, "/api/"):
			w.WriteHeader(500)
			fmt.Fprint(w, "Error: Unexpected path")
		case strings.HasPrefix(p, "/solo/"):
			w.WriteHeader(500)
			fmt.Fprint(w, "Error: Unexpected path")
		case p == "/about" || p == "/team":
			fmt.Fprint(w, "a real page: "+p)
		default:
			fmt.Fprint(w, "<html><title>App</title><body>the same shell for every route</body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), log...) }
}

// A directory that holds two hits is asked one name that cannot exist, a
// random name under that directory, once every word of the sweep has been
// asked; a directory with one hit is not, and a wordlist with no slash in any
// word asks none.
func TestSweepAsksOneNameThatCannotExistInADirectoryOfTwoHitsAfterTheWords(t *testing.T) {
	fetch.Reset()
	srv, asked := orderedServer(t)
	words := []string{"api/users", "api/items", "api/foo", "solo/only", "about", "team", "nothing", "api/bar"}
	c := New(srv.Client(), Options{Words: words, Rate: 1000, Set: allStatuses()})
	_, summary := sweepRows(t, c, srv.URL+"/")
	log := asked()
	isWord := map[string]bool{}
	for _, w := range words {
		isWord["/"+w] = true
	}
	lastWord, controls := -1, []int{}
	for i, p := range log {
		switch {
		case isWord[p]:
			lastWord = i
		case strings.HasPrefix(p, "/api/"), strings.HasPrefix(p, "/solo/"):
			controls = append(controls, i)
		}
	}
	if len(controls) != 1 || log[controls[0]] == "" || !strings.HasPrefix(log[controls[0]], "/api/") {
		t.Fatalf("one control for /api/ (three hits) and none for /solo/ (one hit): %v", log)
	}
	if controls[0] < lastWord {
		t.Errorf("the control was asked before the sweep was through: %v", log)
	}
	if isWord[log[controls[0]]] || summary["controls"] != 1.0 {
		t.Errorf("control %q, summary %v", log[controls[0]], summary)
	}

	// No slash in any word: no control, whatever the hits.
	fetch.Reset()
	srv2, asked2 := orderedServer(t)
	c = New(srv2.Client(), Options{Words: []string{"about", "team", "nothing"}, Rate: 1000, Set: allStatuses()})
	_, summary = sweepRows(t, c, srv2.URL+"/")
	if summary["controls"] != 0.0 || len(asked2()) != 3+4 {
		t.Errorf("a list with no slash: summary %v, %d requests (want 3 words and 4 calibration names)", summary, len(asked2()))
	}
}

// A hit that answers 403 or 404 folds the same way as any other, only when
// the directory's control answered it byte for byte: a 404 or a 403 with
// another body is listed.
func TestSweepFoldsA403Or404HitOnlyWhenTheControlAnsweredItByteForByte(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/gone/real":
			w.WriteHeader(404)
			fmt.Fprint(w, "this one has a page of its own")
		case strings.HasPrefix(p, "/gone/"):
			w.WriteHeader(404)
			fmt.Fprint(w, "nothing here")
		case p == "/priv/special":
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden for you in particular")
		case strings.HasPrefix(p, "/priv/"):
			w.WriteHeader(403)
			fmt.Fprint(w, "Forbidden")
		default:
			fmt.Fprint(w, "<html><title>App</title><body>the same shell for every route</body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	set := fuzz.NewSet(nil)
	_ = set.AddMatcher("status", "all")
	words := []string{"gone/a", "gone/b", "gone/real", "priv/a", "priv/b", "priv/special"}
	c := New(srv.Client(), Options{Words: words, Rate: 1000, Set: set})
	rows, _ := sweepRows(t, c, srv.URL+"/")
	for p, want := range map[string]bool{"/gone/a": true, "/gone/b": true, "/gone/real": false, "/priv/a": true, "/priv/b": true, "/priv/special": false} {
		m := rows[p]
		if m == nil {
			t.Errorf("%s has no row", p)
			continue
		}
		if folded := m["catchall"] == true; folded != want {
			t.Errorf("%s: folded %v, want %v (%v)", p, folded, want, m)
		}
	}
}
