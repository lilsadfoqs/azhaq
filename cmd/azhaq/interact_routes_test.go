package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/collectors/crawlcol"
	"github.com/lilsadfoqs/azhaq/internal/collectors/rendercol"
	"github.com/lilsadfoqs/azhaq/types"
)

func urlObs(collector, url, seen, role string) types.StoredObservation {
	p, _ := json.Marshal(map[string]any{"url": url, "seen": seen, "role": role, "clicked": seen == "click"})
	return types.StoredObservation{Observation: types.Observation{Collector: collector, Kind: "url", Payload: p}}
}

func TestClickRoutesCountsByRouteIdentity(t *testing.T) {
	const h = "http://127.0.0.1:3001/"
	obs := []types.StoredObservation{
		urlObs(crawlcol.Name, h+"api/Feedbacks", "", ""),
		urlObs(rendercol.Name, h+"api/Feedbacks/", "click", "api"), // a slash variant of a listed route
		urlObs(rendercol.Name, h+"assets/x-", "click", "page"),     // a catch-all answer
		urlObs(rendercol.Name, h+"rest/memories/", "click", "api"), // a new route, named two ways
		urlObs(rendercol.Name, h+"rest/memories", "click", "api"),
		urlObs(rendercol.Name, h+"#/about", "click", "client-route"),
		urlObs(rendercol.Name, h+"#/about", "click", "client-route"),
	}
	rows := []engine.MapEntry{{Entity: types.Entity{Type: types.TypeURL, Key: h + "assets/x-"}, Coverage: "catchall"}}
	found, left := clickRoutes(obs, rows)
	if found != 2 || left != 2 {
		t.Errorf("found %d, left %d; want 2 routes (rest/memories, #/about) and 2 left out", found, left)
	}
	note := strings.Join(interactNotes(append(obs, types.StoredObservation{Observation: types.Observation{Kind: "interact", Payload: []byte(`{"clicks":5}`)}}), rows), "")
	if !strings.Contains(note, "found 2 routes") || !strings.Contains(note, " more addresses") {
		t.Errorf("note: %s", note)
	}
}

// A single-page app: the front page links /api/items, a button goes to the
// slash variant, another to a path the app answers with its shell.
func interactSPA(realRoute bool) *httptest.Server {
	const shell = `<html><title>app</title><body><a href="/api/items">Items</a>
<button onclick="location.assign('/'+'%s')">Go</button></body></html>`
	target := "api/items/"
	if realRoute {
		target = "real-page"
	}
	const second = `<html><title>app</title><body><a href="/api/items">Items</a>
<button onclick="location.assign('/api/'+'items/')">Go</button><button onclick="location.assign('/nowhere-'+'9f3')">More</button></body></html>`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/items", "/api/items/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"items":[]}`)
		case "/real-page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>real</title><body>a page of its own</body></html>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			if realRoute {
				fmt.Fprintf(w, shell, target)
			} else {
				fmt.Fprint(w, second)
			}
		}
	}))
}

func interactNote(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "1", "-browser", "-interact", "-interact-clicks", "4", "-allow", "127.0.0.1", "-json", "-db", "c.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, n := range lastReport(t, errOut).Notes {
		if strings.HasPrefix(n, "-interact: ") {
			return n
		}
	}
	t.Fatalf("no -interact note:\n%s", errOut)
	return ""
}

func TestInteractCountsNoRouteForASlashVariantOrACatchAll(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := interactSPA(false)
	defer srv.Close()
	if n := interactNote(t, srv); !strings.Contains(n, "found 0 routes") || !strings.Contains(n, " more addresses") {
		t.Errorf("a slash variant of a listed route or a catch-all is counted, or not reached: %s", n)
	}
}

func TestInteractCountsARouteOnlyAClickFound(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := interactSPA(true)
	defer srv.Close()
	if n := interactNote(t, srv); !strings.Contains(n, "found 1 routes") {
		t.Errorf("the new route is not counted: %s", n)
	}
}
