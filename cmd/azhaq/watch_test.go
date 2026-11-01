package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// capture runs f with stdout going to a pipe and returns what it wrote.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := f()
	os.Stdout = stdout
	w.Close()
	out := <-done
	if ferr != nil {
		t.Fatal(ferr)
	}
	return out
}

func TestWatchReportsOnlyWhatChanged(t *testing.T) {
	var mu sync.Mutex
	links := `<a href="/a">a</a>`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html><title>site</title><body>" + links + "</body></html>"))
		case "/a", "/b":
			w.Write([]byte("<html><title>" + r.URL.Path + "</title></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	var hooks []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		hooks = append(hooks, m["text"].(string))
		mu.Unlock()
	}))
	defer hook.Close()

	db := filepath.Join(t.TempDir(), "ws.db")
	watch := func() map[string]any {
		out := capture(t, func() error {
			return cmdWatch([]string{"-db", db, "-json", "-notify", hook.URL, "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
		})
		var ch map[string]any
		if err := json.Unmarshal([]byte(out), &ch); err != nil {
			t.Fatalf("%v: %q", err, out)
		}
		return ch
	}
	if first := watch(); first["baseline"] != true {
		t.Fatalf("first run %v", first)
	}
	mu.Lock()
	links += `<a href="/b">b</a>`
	mu.Unlock()
	second := watch()
	urls, _ := second["urls"].([]any)
	if len(urls) != 1 || !strings.HasSuffix(urls[0].(string), "/b") || second["hosts"] != nil {
		t.Fatalf("second run %v", second)
	}
	third := watch()
	if third["urls"] != nil || third["services"] != nil {
		t.Fatalf("an unchanged run reported %v", third)
	}
	// /a goes away: the link and the page.
	mu.Lock()
	links = `<a href="/b">b</a>`
	mu.Unlock()
	fourth := watch()
	gone, _ := fourth["gone_urls"].([]any)
	if len(gone) != 1 || !strings.HasSuffix(gone[0].(string), "/a") {
		t.Fatalf("a removed page is reported: %v", fourth)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hooks) != 2 || !strings.Contains(hooks[0], "+ 1 URLs") || !strings.Contains(hooks[1], "- 1 URLs gone") {
		t.Errorf("webhook calls %q (the baseline and the unchanged run must not notify)", hooks)
	}
}

// A notification is a request to a third party: the receiver's count is the
// ledger's notification lines is the watch summary's, and the webhook's path
// and query, which are its secret, are in none of them.
func TestWatchNotificationsAreInTheLedgerAndTheSummary(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><title>site</title></html>"))
	}))
	defer site.Close()
	for _, status := range []int{200, 500} { // 500: three tries, each its own line
		var got atomic.Int32
		hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.Add(1)
			w.WriteHeader(status)
		}))
		db := filepath.Join(t.TempDir(), "ws.db")
		url := hook.URL + "/hook/secret-path?token=not-for-output"
		_, errOut, err := captureBoth(t, func() error {
			return cmdWatch([]string{"-db", db, "-json", "-always", "-notify", url, "-notify-rate", "0", "--", "-url", site.URL + "/", "-probe", "-no-paths", "-depth", "0"})
		})
		hook.Close()
		if status == 200 && err != nil || status == 500 && exitCode(err) != exitPartial {
			t.Fatalf("status %d: %v", status, err)
		}
		rep := lastReport(t, errOut)
		if rep.Command != "watch" || rep.Results != int(got.Load()) || got.Load() == 0 {
			t.Errorf("status %d: the receiver got %d requests, the watch summary says %d (%s)", status, got.Load(), rep.Results, rep.Command)
		}
		var notes int
		var hosts string
		if err := ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
			if e.Class == ledger.ClassSource && e.Kind == "http" && e.Method == "POST" {
				notes++
				hosts += e.Target
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if notes != int(got.Load()) {
			t.Errorf("status %d: the receiver got %d requests, the ledger lists %d", status, got.Load(), notes)
		}
		if strings.Contains(hosts, "secret-path") || strings.Contains(hosts, "not-for-output") || !strings.Contains(hosts, strings.TrimPrefix(hook.URL, "http://")+"/…") {
			t.Errorf("status %d: the ledger names the webhook as %q", status, hosts)
		}
		if raw, _ := os.ReadFile(db + ".ledger.jsonl"); strings.Contains(string(raw), "not-for-output") {
			t.Errorf("status %d: the token is in the ledger", status)
		}
		if c, err := ledger.Verify(db + ".ledger.jsonl"); err != nil || c.Unsealed != 0 {
			t.Errorf("status %d: the ledger does not verify as sealed: %+v %v", status, c, err)
		}
		if status == 500 && got.Load() != 3 {
			t.Errorf("a failing webhook was tried %d times, want 3", got.Load())
		}
	}
}
