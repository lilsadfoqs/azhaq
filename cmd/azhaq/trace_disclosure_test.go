package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// A dirs pass that lists a path whose answer holds a stack trace reports it
// in `report -findings` as a proved error-disclosure of low severity, with the
// URL, the status, the first exception line and the frame count, and sends
// nothing for it. Prose about a trace and a plain error page give none.
func TestDirsFindsAStackTraceInAnAnswerAlreadyReceived(t *testing.T) {
	var asked atomic.Int64
	var mu sync.Mutex
	perPath := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		mu.Lock()
		perPath[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/", "/ok":
			fmt.Fprint(w, "hello world")
		case "/boom":
			w.WriteHeader(500)
			fmt.Fprint(w, "java.lang.NullPointerException: user is null\n\tat com.shop.UserController.get(UserController.java:42)\n\tat com.shop.Dispatcher.run(Dispatcher.java:10)\n\tat com.shop.Main.main(Main.java:5)\n")
		case "/py":
			w.WriteHeader(500)
			fmt.Fprint(w, "Traceback (most recent call last):\n  File \"app.py\", line 3, in f\n    g()\n  File \"app.py\", line 6, in g\n    h()\n  File \"app.py\", line 9, in h\n    1/0\nZeroDivisionError: division by zero\n")
		case "/docs":
			fmt.Fprint(w, "<p>A trace lists frames such as at com.shop.UserController.get(UserController.java:42) and at a.B.c(B.java:1), one per line.</p>")
		case "/plain":
			w.WriteHeader(500)
			fmt.Fprint(w, "Internal Server Error")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "d.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wlist(t, "ok", "boom", "py", "docs", "plain", "missing"), "-mc", "all", "-ac=false", "-json", "-ledger", "off", "-db", db})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	mu.Lock()
	if perPath["/boom"] != 1 || perPath["/py"] != 1 {
		t.Errorf("the traces' paths were asked %d and %d times, want once each: nothing more is sent for a trace", perPath["/boom"], perPath["/py"])
	}
	mu.Unlock()
	sent := asked.Load()
	out, errOut, err := captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if asked.Load() != sent {
		t.Errorf("report sent %d requests", asked.Load()-sent)
	}
	findings, _ := parseFindingLines(t, []byte(out))
	got := map[string]map[string]any{}
	for _, f := range findings {
		got[strings.TrimPrefix(f["url"].(string), srv.URL)] = f
	}
	if len(got) != 2 || len(findings) != 2 {
		t.Fatalf("findings %v, want /boom and /py only", out)
	}
	for path, want := range map[string][]string{
		"/boom": {"HTTP 500", "java.lang.NullPointerException: user is null", "3 java frames"},
		"/py":   {"HTTP 500", "ZeroDivisionError: division by zero", "3 python frames"},
	} {
		f := got[path]
		if f == nil || f["kind"] != "error-disclosure" || f["label"] != "proved" || f["severity"] != "low" || f["host"] != "127.0.0.1" {
			t.Errorf("%s: %v, want a proved error-disclosure of low severity", path, f)
			continue
		}
		for _, w := range want {
			if !strings.Contains(f["evidence"].(string), w) {
				t.Errorf("%s: evidence %q lacks %q", path, f["evidence"], w)
			}
		}
	}
}
