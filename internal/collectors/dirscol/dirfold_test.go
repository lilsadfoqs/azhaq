package dirscol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/types"
)

// foldServer is the stand-in of the single-page app: every unknown path answers
// the shell, but inside /api/ every unknown name answers 500 with one
// message, inside /priv/ 403, and inside /echo/ a page that names the path
// asked; /api/users and /api/items are real routes.
func foldServer(t *testing.T) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/api/users":
			fmt.Fprint(w, `{"users":[1,2,3]}`)
		case p == "/api/items":
			fmt.Fprint(w, `{"items":["a"]}`)
		case strings.HasPrefix(p, "/api/"):
			w.WriteHeader(500)
			fmt.Fprint(w, "Error: Unexpected path")
		case strings.HasPrefix(p, "/priv/"):
			w.WriteHeader(403)
			fmt.Fprint(w, "Forbidden")
		case strings.HasPrefix(p, "/echo/"):
			w.WriteHeader(500)
			fmt.Fprintf(w, "Cannot GET %s", p)
		case p == "/one/only":
			w.WriteHeader(500)
			fmt.Fprint(w, "Error: Unexpected path")
		case p == "/real/a":
			fmt.Fprint(w, "the first real page")
		case p == "/real/b":
			fmt.Fprint(w, "another real page, longer")
		default:
			fmt.Fprint(w, "<html><title>App</title><body>the same shell for every route</body></html>")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range asked {
			out[k] = v
		}
		return out
	}
}

func sweepRows(t *testing.T, c *Collector, base string) (map[string]map[string]any, map[string]any) {
	t.Helper()
	rows := map[string]map[string]any{}
	var summary map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": base}}, func(o types.Observation) error {
		var m map[string]any
		_ = json.Unmarshal(o.Payload, &m)
		switch o.Kind {
		case "dirs":
			summary = m
		case "url":
			rows[strings.TrimPrefix(m["url"].(string), strings.TrimSuffix(base, "/"))] = m
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows, summary
}

// Hits that share a directory the sweep did not start in get one control
// there (a random name under it): the hits whose answer is the control's byte
// for byte are marked with it, the others stay; the control is one request,
// counted in the summary, and a directory with a single hit is not asked.
func TestSweepFoldsHitsThatAreTheirDirectorysControl(t *testing.T) {
	fetch.Reset()
	srv, asked := foldServer(t)
	words := []string{"api/users", "api/items", "api/notAPathXYZ", "api/foo", "api/bar", "priv/a", "priv/b", "priv/c",
		"echo/x", "echo/y", "one/only", "real/a", "real/b", "nothing"}
	c := New(srv.Client(), Options{Words: words, Rate: 1000, Set: allStatuses()})
	rows, summary := sweepRows(t, c, srv.URL+"/")
	folded := map[string]string{}
	for p, m := range rows {
		if m["catchall"] == true {
			ctl := m["control"].(map[string]any)
			if m["control_exact"] != true || !strings.HasPrefix(ctl["url"].(string), srv.URL+p[:strings.LastIndex(p, "/")+1]) {
				t.Errorf("%s: control %v", p, m)
			}
			folded[p] = fmt.Sprint(ctl["status"])
		}
	}
	want := map[string]string{"/api/notAPathXYZ": "500", "/api/foo": "500", "/api/bar": "500", "/priv/a": "403", "/priv/b": "403", "/priv/c": "403", "/echo/x": "500", "/echo/y": "500"}
	if fmt.Sprint(folded) != fmt.Sprint(want) {
		t.Errorf("folded %v, want %v", folded, want)
	}
	for _, p := range []string{"/api/users", "/api/items", "/real/a", "/real/b", "/one/only"} {
		if rows[p] == nil || rows[p]["catchall"] != nil {
			t.Errorf("%s stays listed: %v", p, rows[p])
		}
	}
	if len(rows) != 13 {
		t.Errorf("%d rows, every hit is still a row", len(rows))
	}
	// 14 words, 4 calibration names, and a control for /api/, /priv/, /echo/ and /real/.
	total := 0
	for _, n := range asked() {
		total += n
	}
	if total != 14+4+4 || summary["controls"] != 4.0 || summary["folded"] != 8.0 {
		t.Errorf("%d requests, summary %v", total, summary)
	}
	// Calibration off is the user's own: no control is asked.
	c = New(srv.Client(), Options{Words: words, Rate: 1000, NoCalibration: true, Set: allStatuses()})
	rows, summary = sweepRows(t, c, srv.URL+"/")
	for p, m := range rows {
		if m["catchall"] != nil {
			t.Errorf("-ac=false folded %s", p)
		}
	}
	if summary["controls"] != 0.0 {
		t.Errorf("-ac=false asked controls: %v", summary)
	}
}

func allStatuses() *fuzz.Set {
	set := fuzz.NewSet(nil)
	_ = set.AddMatcher("status", "all")
	_ = set.AddFilter("status", "404")
	return set
}

// The blank word asks for the base URL, as in ffuf, and the base is judged
// as every word is: it is not a hit when it answers like a path that cannot
// exist. Each case is what ffuf v2.1.0 printed with -ac -mc all on the same
// stand-in, with a wordlist whose first line is empty; the last differs on
// purpose.
func TestBlankWordIsJudgedLikeAnyWord(t *testing.T) {
	const shell = "<html><title>app</title><body>single page app shell</body></html>"
	for _, c := range []struct {
		name  string
		serve func(w http.ResponseWriter, p string)
		want  string
	}{
		{"a catch-all page: the base is the control's page", func(w http.ResponseWriter, p string) {
			if p == "/openapi.json" {
				fmt.Fprint(w, `{"openapi":"3.0"}`)
				return
			}
			fmt.Fprint(w, shell)
		}, "/openapi.json"},
		{"a page for the base and a 404 for the rest: the base is a hit", func(w http.ResponseWriter, p string) {
			switch p {
			case "/openapi.json":
				fmt.Fprint(w, `{"openapi":"3.0"}`)
			case "/":
				fmt.Fprint(w, shell)
			default:
				w.WriteHeader(404)
				fmt.Fprint(w, `{"detail":"Not Found"}`)
			}
		}, "/ /openapi.json"},
		// ffuf calibrates on the size alone: the base's 200 with the 404
		// shell's size is dropped. azhaq compares the status too, so the
		// base is listed: it answers 200 where a path that cannot exist
		// answers 404.
		{"a 404 with the base's own page: azhaq lists the base, ffuf does not", func(w http.ResponseWriter, p string) {
			switch p {
			case "/openapi.json":
				fmt.Fprint(w, `{"openapi":"3.0"}`)
			case "/":
				fmt.Fprint(w, shell)
			default:
				w.WriteHeader(404)
				fmt.Fprint(w, shell)
			}
		}, "/ /openapi.json"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fetch.Reset()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.serve(w, r.URL.Path) }))
			defer srv.Close()
			cl := New(srv.Client(), Options{Words: []string{"", "openapi.json", "zzz"}, Rate: 1000, Set: allStatuses()})
			got, _ := sweepOf(t, cl, srv.URL+"/")
			if strings.Join(got, " ") != c.want {
				t.Errorf("hits %v, want %q", got, c.want)
			}
		})
	}
}

// A hit that is folded is the control's answer, so it is not a directory to
// sweep into, though it redirects to itself with a slash as directories do:
// here every name under /slash/ does.
func TestSweepDoesNotDescendIntoAFoldedHit(t *testing.T) {
	fetch.Reset()
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/slash/") && !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		}
		fmt.Fprint(w, "x")
	}))
	t.Cleanup(srv.Close)
	c := New(srv.Client(), Options{Words: []string{"slash/a", "slash/b"}, Depth: 3, Rate: 1000, Set: allStatuses()})
	rows, _ := sweepRows(t, c, srv.URL+"/")
	for _, p := range []string{"/slash/a", "/slash/b"} {
		if rows[p]["catchall"] != true {
			t.Errorf("%s is the control's answer: %v", p, rows[p])
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for p := range asked {
		if strings.HasPrefix(p, "/slash/a/") || strings.HasPrefix(p, "/slash/b/") {
			t.Errorf("a folded hit was swept into: %s", p)
		}
	}
}
