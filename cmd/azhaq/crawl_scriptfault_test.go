package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/browser"
)

// An app whose script address answers its HTML shell (as an app server
// does for an address it cannot map, or when a proxy sends it the full
// address) draws no menu: the summary says the script did not load and why,
// not only that nothing showed.
func TestBrowserSaysWhenAScriptIsAnsweredWithAPage(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>shop</title><body><div id=app></div><script type="module" src="/app.js"></script></body></html>`)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "1", "-browser", "-interact", "-allow", "127.0.0.1", "-json", "-db", "c.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, want := range []string{"did not load as JavaScript", srv.URL + "/app.js", "-interact: 0 clicks"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the summary lacks %q:\n%s", want, errOut)
		}
	}
}
