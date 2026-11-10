package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
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

// An app that answers every unknown path with its shell answers its script
// addresses with it too: they are folded as the catch-all, counted with the
// control they matched, not listed as script hints.
func TestBrowserFoldsScriptsAnsweredWithTheCatchAllPage(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>shop</title><body><div id=app></div><script type="module" src="/assets/i18n/chunk-AB12.js"></script><script src="/ws/main.js"></script></body></html>`)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-d", "1", "-browser", "-interact", "-allow", "127.0.0.1", "-db", "c.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, js := range []string{"/assets/i18n/chunk-AB12.js", "/ws/main.js"} {
		if strings.Contains(out, srv.URL+js) {
			t.Errorf("%s is listed:\n%s", js, out)
		}
	}
	if want := "folded catchall: 2 URLs of " + srv.URL + " answer as the control does: GET /assets/"; !strings.Contains(out+errOut, want) {
		t.Errorf("no line %q:\n%s\n%s", want, out, errOut)
	}
	q, _, _ := cli(t, "query", "-db", "c.db", "-type", "URL", "-fields", "key,coverage,role", "-json")
	for _, js := range []string{"/assets/i18n/chunk-AB12.js", "/ws/main.js"} {
		if want := `"coverage":"catchall","key":"` + srv.URL + js + `","role":"script"`; !strings.Contains(q, want) {
			t.Errorf("no row %s:\n%s", want, q)
		}
	}
}
