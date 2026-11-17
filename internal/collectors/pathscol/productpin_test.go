package pathscol

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

var updatePin = flag.Bool("update-pin", false, "rewrite testdata/productpin.golden")

// pinReal are pages a few product paths really serve.
var pinReal = map[string]string{
	"/status.php":              `{"installed":true,"version":"10.12.1.3","versionstring":"10.12.1","edition":"Community","productname":"ownCloud"}`,
	"/webclient/":              `<html> <title>3CX Webclient</title> <meta name="description" content="3CX"></html>`,
	"/console/hawtconfig.json": `<html>img/activemq.png ActiveMQ Artemis Apache Artemis</html>`,
	"/+CSCOE+/logon.html":      `<html>/+CSCOU+/portal.css SSL VPN Service</html>`,
	"/vpn/index.html":          `<html><title>Citrix Gateway</title></html>`,
	"/dotAdmin/":               `<html><title>dotCMS Content Management Platform</title></html>`,
}

// pinSite is a site that answers every path with page (when catchAll) and
// the paths of real with their own pages.
func pinSite(page string, catchAll bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := pinReal[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if catchAll || r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(page))
			return
		}
		http.NotFound(w, r)
	}))
}

// pinPage is an application page of about size bytes. With marks it names
// products in its text, as an app page that quotes a library does.
func pinPage(size int, marks bool) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><title>Shop</title><script src="/main.js"></script></head><body><app-root></app-root>`)
	if marks {
		b.WriteString(`<title>Bazarr</title><p>Central Authentication Service</p><p>ActiveAdmin active_admin_content active_admin-</p>`)
	}
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, `<div class="row"><a href="/#/item-%d">Latest headlines and weekly reports %d</a></div>`, i%50, i)
	}
	b.WriteString(`</body></html>`)
	return b.String()
}

// pinRun is what a root sweep of the site at base names: one line for each
// path whose answer matched, then the sweep's counts and the rows of the map.
func pinRun(t *testing.T, base string) []string {
	t.Helper()
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	col := &Collector{Client: http.DefaultClient, Wordlist: []string{"login", "admin"}, ProductChecks: true}
	var out []string
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": base + "/"}}, func(o types.Observation) error {
		var p map[string]any
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case DetectedKind:
			rows, _ := json.Marshal(p["detected"])
			out = append(out, fmt.Sprintf("detected %v %v %s", p["path"], p["status"], rows))
		case SweepKind:
			delete(p, "origin")
			rec, _ := json.Marshal(p)
			out = append(out, "sweep "+string(rec))
		case "url":
			out = append(out, fmt.Sprintf("map %v %v", p["path"], p["status"]))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// What the product checks name on three stand-in sites is pinned: an app
// page that matches nothing, one that quotes products, and a site that
// answers 404 to a path it does not have, each with a few real product
// pages. A change that makes product checks cheaper must leave it as it
// is (#505). The names come from the embedded templates: a refresh of them
// changes the file, and -update-pin rewrites it.
func TestProductChecksNameWhatTheyNamed(t *testing.T) {
	var got []string
	for _, site := range []struct {
		name     string
		page     string
		catchAll bool
	}{
		{"spa", pinPage(10<<10, false), true},
		{"spa-marked", pinPage(10<<10, true), true},
		{"notfound", pinPage(2<<10, false), false},
	} {
		srv := pinSite(site.page, site.catchAll)
		t.Cleanup(srv.Close)
		for _, l := range pinRun(t, srv.URL) {
			got = append(got, site.name+" "+l)
		}
	}
	const file = "testdata/productpin.golden"
	text := strings.Join(got, "\n") + "\n"
	if *updatePin {
		if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if text != string(want) {
		wl, gl := strings.Split(string(want), "\n"), strings.Split(text, "\n")
		for _, l := range wl {
			if !slices.Contains(gl, l) {
				t.Errorf("no longer named: %s", l)
			}
		}
		for _, l := range gl {
			if !slices.Contains(wl, l) {
				t.Errorf("named now, not before: %s", l)
			}
		}
	}
}
