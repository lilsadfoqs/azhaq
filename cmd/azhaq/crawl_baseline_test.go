package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/fetch"
)

// A single-page app whose script calls routes in many directories, as
// Juice Shop's does; every unknown path under /rest/ and /api/ answers with
// an error page. probes counts the requests for a path that does not exist.
func spaWithManyDirs(probes *atomic.Int32) *httptest.Server {
	calls := []string{"/rest/user/whoami", "/rest/user/login", "/rest/admin/version", "/rest/products/search",
		"/rest/basket/1", "/rest/memories/", "/api/Users", "/api/v2/things/list", "/api/v2/other/list", "/assets/i18n/en.json"}
	var js strings.Builder
	js.WriteString("var r={useHash:!0};")
	for _, c := range calls {
		fmt.Fprintf(&js, "fetch('%s');", c)
	}
	known := map[string]bool{}
	for _, c := range calls {
		known[c] = true
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, fetch.ProbeToken()) {
			probes.Add(1)
		}
		switch {
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, js.String())
		case known[r.URL.Path]:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
		case strings.HasPrefix(r.URL.Path, "/rest/") || strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/assets/"):
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "<title>Error</title>Unexpected path: %s", r.URL.Path)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><title>Shop</title><app-root></app-root><script src="main.js"></script>`)
		}
	}))
}

func crawlRows(t *testing.T, args ...string) (rows int, probes int32) {
	t.Helper()
	var n atomic.Int32
	srv := spaWithManyDirs(&n)
	defer srv.Close()
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, append([]string{"crawl", "-u", srv.URL + "/", "-d", "1", "-silent", "-allow", "127.0.0.1"}, args...)...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	return len(strings.Fields(out)), n.Load()
}

// A crawl asks the root and each top-level directory what an unknown path
// answers, not every directory down the tree: 4 requests here, not 11. The
// URLs it lists are the same, and -sweep keeps the check of every directory.
func TestCrawlAsksTheCatchAllBaselineOfTopLevelDirectoriesOnly(t *testing.T) {
	shallow, np := crawlRows(t)
	full, nf := crawlRows(t, "-sweep")
	if np > 4 {
		t.Errorf("%d baseline requests, want at most 4 (the root, /rest/, /api/, /assets/)", np)
	}
	if nf <= np {
		t.Errorf("-sweep sent %d baseline requests, the default %d: -sweep keeps one for every directory", nf, np)
	}
	if shallow < 10 || shallow < full-8 {
		t.Errorf("default crawl listed %d URLs, -sweep %d", shallow, full)
	}
}
