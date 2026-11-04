package urlcol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// The classes of the urls page, each with the examples the page gives: the
// rule that fires is the one the page names, and what the page says stays
// stays.
func TestJunkClassesOfTheUrlsPage(t *testing.T) {
	for class, urls := range map[string][]string{
		"scanner-payload": {
			"http://example.org/t/fit.txt?.tst5-Name/../Gen",
			"http://example.org/a.php?artist=1union%20select%20group_concat%28schema_name%29%20from%20information_schema.schemata",
			"http://example.org/a.php?artist=1union select 1,2 from information_schema.tables",
		},
		"scanner-probe": {
			"http://example.org/acunetix_xsl_inclusion_test.xsl",
			"http://example.org/t/fit.txt?%00",
			"http://example.org/t/fit.txt?.",
			"http://example.org/t/fit.txt?.tst",
			"http://example.org/t/fit.txt?.bak",
		},
		"listing-sort": {"http://example.org/files/?C=N;O=D", "http://example.org/files/?C=M&O=A"},
		"placeholder":  {"http://example.org/rest/basket/NaN", "http://example.org/a/undefined", "http://example.org/a/null/b"},
		"dot-segment":  {"http://example.org/a/..", "http://example.org/a/%2e%2e/b"},
		"malformed": {
			"http://example.org/reports/...", "http://example.org/a/.../b", "http://example.org/reports/…", "http://example.org/a*b",
			"http://example.org/a%22b", "http://example.org/a%27b", "http://example.org/a%3Cb", "http://example.org/a>b",
		},
		"fuzzing": {
			"http://example.org/FUZZ", "http://example.org/FUZ2Z", "http://example.org/a.php?q=FUZZFUZ2Z", "http://example.org/FUZZ.php",
			"http://example.org/a.php?q=FUZZ000003:C=200", "http://example.org/FUZZMultiple", "http://example.org/%CB%93%E2%86%92FUZZ",
			"http://example.org/{payload}/x", "http://example.org/{FUZZ}", "http://example.org/a.php?q={payload}",
			"http://example.org/HTTP/1.0", "http://example.org/HTTP/1.1", "http://example.org/index.php%20HTTP/1.1", "http://example.org/a.php?artist=1HTTP/1.1",
		},
		"cut-link": {
			"http://example.org/reports/2307813.", "http://example.org/a,", "http://example.org/a;", "http://example.org/a'",
			"http://example.org/a)", "http://example.org/a]", "http://example.org/a?b=c.",
		},
	} {
		for _, u := range urls {
			_, why, ok := cleanWhy(u, "example.org", false)
			if ok || junkClass(why) != class {
				t.Errorf("%s: kept=%v, class %q (%q), want %s", u, ok, junkClass(why), why, class)
			}
		}
	}
	for _, u := range []string{
		"http://example.org/t/fit.txt?.tst5-Name&next=../home", "http://example.org/a?next=../home",
		"http://example.org/fuzz", "http://example.org/a?q=fuzz", "http://example.org/FUZZY", "http://example.org/FUZZ-list.txt",
		"http://example.org/a?proto=HTTP/1.1", "http://example.org/users/{id}", "http://example.org/docs/http/1.1",
		"http://example.org/a(b)", "http://example.org/a.php?q=1", "http://example.org/a?b=c",
	} {
		if _, why, ok := cleanWhy(u, "example.org", false); !ok {
			t.Errorf("%s stays, but is junk: %s", u, why)
		}
	}
}

// A static file (an image, a font, a style sheet, anything on a media host
// with an opaque name) is labelled asset with the page's reason; a page or an
// API is not labelled.
func TestStaticFilesAreLabelledAssets(t *testing.T) {
	for u, class := range map[string]string{
		"http://example.org/img/logo.png":                      "asset",
		"http://example.org/fonts/a.woff2":                     "asset",
		"http://example.org/css/site.css":                      "asset",
		"https://photos.example.org/variants/9f8e7d6c5b4a3210": "asset",
		"http://example.org/products/42":                       "",
		"http://example.org/api/v1/users":                      "",
	} {
		c, reason := label("", u)
		if c != class || (class == "asset") != (reason == "static file (by extension or media host): no route sits behind it") || (class == "" && reason != "") {
			t.Errorf("%s: class %q reason %q, want class %q", u, c, reason, class)
		}
	}
}

// The graph holds one example for each URL shape: 90 archived URLs of three
// shapes are three rows, and the summary's count still says 90.
func TestGraphHoldsOneExampleForEachURLShape(t *testing.T) {
	var rows []string
	for i := 1; i <= 30; i++ {
		rows = append(rows, fmt.Sprintf(`["http://lab7shape.org/item/%d"]`, i), fmt.Sprintf(`["http://lab7shape.org/user/%d/profile"]`, 100+i), fmt.Sprintf(`["http://lab7shape.org/view.php?id=%d"]`, 7000+i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "0" {
			fmt.Fprintf(w, `[["original"],%s]`, strings.Join(rows, ","))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	waybackBase = srv.URL
	c := New(Options{Client: srv.Client(), Only: []string{"wayback"}})
	c.pauses = nil
	var examples []string
	total := 0
	if _, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "lab7shape.org"}}, func(o types.Observation) error {
		var p struct {
			URL   string `json:"url"`
			Count int    `json:"count"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case "url":
			examples = append(examples, p.URL)
		case "urls":
			total = p.Count
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(examples) != 3 || total != 90 {
		t.Errorf("%d examples %v of %d archived URLs, want 3 of 90", len(examples), examples, total)
	}
}
