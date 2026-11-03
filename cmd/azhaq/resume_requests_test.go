package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// spaStandIn answers like a single-page app: every route returns the shell,
// the script names a few API routes, and the API answers JSON. It counts the
// requests it receives.
func spaStandIn(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		p := r.URL.Path
		switch {
		case p == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			var b strings.Builder
			for i := 0; i < 20; i++ {
				fmt.Fprintf(&b, `{path:"page%d",c:x},`, i)
			}
			b.WriteString(`fetch("/api/Products");fetch("/rest/products/search?q=");fetch("/rest/user/whoami");fetch("/rest/basket/1");`)
			fmt.Fprint(w, b.String())
		case p == "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /ftp\n")
		case strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/rest/"):
			w.Header().Set("Content-Type", "application/json")
			if strings.Count(p, "/") > 2 {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"error":"not found"}`)
				return
			}
			fmt.Fprint(w, `{"status":"success","data":[{"id":1}]}`)
		default:
			fmt.Fprint(w, `<!doctype html><html><head><title>Shop</title><script src="main.js"></script></head><body><app-root></app-root></body></html>`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// A run stopped by -max-requests and resumed until nothing is left sends
// about what one run sends: the sweep of an origin goes to the task that
// started it, so what the first process swept is not swept again from
// another URL.
func TestStoppedAndResumedRunSendsWhatOneRunSends(t *testing.T) {
	srv, got := spaStandIn(t)
	t.Chdir(t.TempDir())
	if _, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-db", "one.db"); code != exitOK {
		t.Fatalf("one run: exit %d, stopped %q", code, rep.Stopped)
	}
	one := got.Load()
	if one < 60 {
		t.Fatalf("the stand-in is too small to cut: one run sent %d", one)
	}
	got.Store(0)
	budget := fmt.Sprint(one / 4)
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-db", "cut.db", "-max-requests", budget)
	if code != exitLimit {
		t.Fatalf("the cut run: exit %d, stopped %q", code, rep.Stopped)
	}
	for i := 0; code == exitLimit && i < 20; i++ {
		_, rep, code = runContract(t, "resume", "-db", "cut.db", "-max-requests", budget)
	}
	if code != exitOK {
		t.Fatalf("resume did not finish: exit %d, stopped %q", code, rep.Stopped)
	}
	t.Logf("one run %d, cut and resumed %d", one, got.Load())
	if all := got.Load(); float64(all) > 1.1*float64(one) {
		t.Errorf("a stopped and resumed run sent %d requests, one run %d (more than 10%% over)", all, one)
	}
}
