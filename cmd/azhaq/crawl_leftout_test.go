package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A page with a stylesheet, an image and a link.
func leftOutSite(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<link rel=stylesheet href=/styles.css><a href=/a>a</a><img src=/logo.png>`)
		case "/a":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html>a</html>`)
		case "/styles.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `body{}`)
		case "/logo.png":
			w.Header().Set("Content-Type", "image/png")
			fmt.Fprint(w, "png")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The class counts are of every row of the map; the rows the default
// extension list leaves out are counted in the summary too, so the printed
// rows and what was left out add up to the classes.
func TestCrawlSummaryCountsTheRowsTheExtensionListLeftOut(t *testing.T) {
	srv := leftOutSite(t)
	classes := func(counts map[string]any) int {
		n := 0
		for _, k := range []string{"observed routes", "linked routes", "hint routes", "named strings"} {
			f, _ := counts[k].(float64)
			n += int(f)
		}
		return n
	}
	out, errOut := crawlOut(t, srv, "-json", "-hints")
	sum := sumMap(t, errOut)
	counts, _ := sum["counts"].(map[string]any)
	printed := len(strings.Split(strings.TrimSpace(out), "\n"))
	if counts["left out by the extension list"] != 1.0 {
		t.Errorf("the logo is left out by the extension list: %v", counts)
	}
	if got := printed + 1; got != classes(counts) {
		t.Errorf("%d rows printed and 1 left out, the classes say %d (%v)", printed, classes(counts), counts)
	}
	if !strings.Contains(errOut, "1 row was left out of the list by the default extension list") || !strings.Contains(errOut, "-assets lists") {
		t.Errorf("no note says what the extension list left out: %s", errOut)
	}
	// -assets lists them: nothing is left out, and the rows are the classes.
	out, errOut = crawlOut(t, srv, "-json", "-hints", "-assets")
	counts, _ = sumMap(t, errOut)["counts"].(map[string]any)
	if printed := len(strings.Split(strings.TrimSpace(out), "\n")); printed != classes(counts) || counts["left out by the extension list"] != nil || strings.Contains(errOut, "default extension list") {
		t.Errorf("-assets: %d rows printed, classes %d, counts %v", printed, classes(counts), counts)
	}
	// A filter the user gave is counted apart, in its own note.
	_, errOut = crawlOut(t, srv, "-json", "-hints", "-fr", "/a$")
	counts, _ = sumMap(t, errOut)["counts"].(map[string]any)
	if counts["left out by -em, -ef, -mr, -fr"] != 1.0 || !strings.Contains(errOut, "1 row was left out of the list by -em, -ef, -mr or -fr") {
		t.Errorf("-fr: %v", counts)
	}
}
