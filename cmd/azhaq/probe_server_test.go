package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every Server line is kept: a proxy in front of the app adds its own, and
// the first alone hides the product behind it. The row says them all, as
// httpx's webserver does, direct, through a proxy and with -fr.
func TestProbeKeepsTheWholeServerHeader(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Server"] = []string{"BaseHTTP/0.6 Python/3.14.4", "Werkzeug/2.2.3 Python/3.11.15"}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>VAmPI</title>"))
	}))
	t.Cleanup(srv.Close)
	const want = "BaseHTTP/0.6 Python/3.14.4 Werkzeug/2.2.3 Python/3.11.15"
	for name, extra := range map[string][]string{
		"direct": nil,
		"proxy":  {"-proxy", forwardProxy(t, strings.TrimPrefix(srv.URL, "http://"))},
		"follow": {"-fr"},
	} {
		out, _, code := runContract(t, append([]string{"probe", "-u", srv.URL + "/", "-json"}, extra...)...)
		rows := probeRows(t, out)
		if code != exitOK || len(rows) != 1 {
			t.Fatalf("%s: exit %d, %s", name, code, out)
		}
		if rows[0]["webserver"] != want {
			t.Errorf("%s: webserver %v, want %q", name, rows[0]["webserver"], want)
		}
	}
}
