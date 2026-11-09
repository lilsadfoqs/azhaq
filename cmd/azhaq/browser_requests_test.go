package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A page that fetches a URL the server never answers, and one outside the
// scope: the summary counts the requests Chrome sent, which of them got an
// answer, and the one it was not let send, and the numbers add up to the
// ledger's Chrome lines.
func TestBrowserRequestsAreCountedAnsweredUnansweredAndBlocked(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>t</title><body><script>
fetch('/api/ok');
fetch('http://203.0.113.9/elsewhere').catch(function(){});
window.addEventListener('load', function(){ setTimeout(function(){ fetch('/hang'); fetch('/hang2'); }, 100); });
</script></body></html>`)
		case "/hang", "/hang2":
			<-r.Context().Done() // a long poll the server never answers
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "shots", "-u", srv.URL+"/", "-dir", "s", "-shot-timeout", "4s", "-db", "c.db", "-allow", "127.0.0.1", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	sum := sumMap(t, errOut)
	b, _ := sum["browser_requests"].(map[string]any)
	if b == nil {
		t.Fatalf("the summary has no browser_requests:\n%s", errOut)
	}
	n := func(k string) int { f, _ := b[k].(float64); return int(f) }
	lines := 0
	var hung []string
	if err := ledger.Read("c.db.ledger.jsonl", func(e ledger.Entry) error {
		if e.Kind == "chrome" {
			lines++
			if strings.Contains(e.Target, "/hang") {
				hung = append(hung, e.Target)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(hung) != 2 {
		t.Fatalf("the ledger lists %v for the two requests nothing answered", hung)
	}
	if n("sent") != lines {
		t.Errorf("sent %d, the ledger has %d browser lines: %v", n("sent"), lines, b)
	}
	if n("answered")+n("unanswered") != n("sent") {
		t.Errorf("answered and unanswered do not add up to sent: %v", b)
	}
	if n("unanswered") != 2 {
		t.Errorf("unanswered %d, want the 2 requests nothing answered: %v", n("unanswered"), b)
	}
	if n("answered") < 2 { // the page and /api/ok
		t.Errorf("answered %d: %v", n("answered"), b)
	}
	if n("blocked") != 1 {
		t.Errorf("blocked %d, want 1 (the request outside the scope): %v", n("blocked"), b)
	}
	if !strings.Contains(errOut, `"browser_requests"`) {
		t.Errorf("no browser_requests in the summary:\n%s", errOut)
	}
}

func TestBrowserRequestsTextLine(t *testing.T) {
	b := &browserRequests{Sent: 46, Answered: 44, Unanswered: 2, Blocked: 3}
	if got, want := b.line(), "browser requests: 46 sent, 44 answered, 2 unanswered, 3 blocked by scope or held"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

// run -browser and crawl -browser say it too, and sent is the ledger's
// Chrome lines whichever command drove Chrome.
func TestBrowserRequestsOfRunAndCrawlAddUpToTheLedger(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>t</title><body><script>fetch('/api/ok'); fetch('http://203.0.113.9/x').catch(function(){})</script></body></html>`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	for i, args := range [][]string{
		{"crawl", "-u", srv.URL + "/", "-d", "1", "-browser", "-no-map-guess"},
		{"run", "-url", srv.URL + "/", "-browser", "-no-map-guess", "-skip", "azhaq-subdomains,azhaq-urls,azhaq-rdap,azhaq-tls"},
	} {
		db := fmt.Sprintf("c%d.db", i)
		_, errOut, code := cli(t, append(args, "-db", db, "-allow", "127.0.0.1", "-json")...)
		if code != exitOK {
			t.Fatalf("%s: exit %d\n%s", args[0], code, errOut)
		}
		b, _ := sumMap(t, errOut)["browser_requests"].(map[string]any)
		if b == nil {
			t.Fatalf("%s: no browser_requests in the summary:\n%s", args[0], errOut)
		}
		n := func(k string) int { f, _ := b[k].(float64); return int(f) }
		lines := 0
		if err := ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
			if e.Kind == "chrome" {
				lines++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if n("sent") != lines || n("answered")+n("unanswered") != lines || n("blocked") != 1 || n("sent") < 2 {
			t.Errorf("%s: %v, the ledger has %d browser lines and 1 refused request", args[0], b, lines)
		}
	}
}
