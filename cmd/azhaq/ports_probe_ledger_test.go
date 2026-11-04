package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A port identification sends probes on the connection it opened. Behind a
// logging server, every request it saw has a ledger line (method and path),
// and the summary still counts the connection once.
func TestPortProbesAreInTheLedger(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server", "probe-test")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	dir := t.TempDir()
	led := filepath.Join(dir, "p.ledger.jsonl")
	_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", u.Port(), "-db", filepath.Join(dir, "p.db"), "-ledger", led, "-json")
	rep := lastReport(t, errOut)
	if code != exitOK {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	var listed []string
	conns, probes := 0, 0
	_ = ledger.Read(led, func(e ledger.Entry) error {
		switch e.Kind {
		case "tcp":
			conns++
		case ledger.KindProbe:
			probes++
			if e.Proto == "http" {
				p, _ := url.Parse(e.Target)
				listed = append(listed, e.Method+" "+p.RequestURI())
			}
		}
		return nil
	})
	mu.Lock()
	defer mu.Unlock()
	sort.Strings(seen)
	sort.Strings(listed)
	if len(seen) == 0 || strings.Join(seen, "\n") != strings.Join(listed, "\n") {
		t.Fatalf("the server saw\n%s\nthe ledger lists\n%s", strings.Join(seen, "\n"), strings.Join(listed, "\n"))
	}
	if probes != len(listed) {
		t.Errorf("%d probe lines, %d of them HTTP", probes, len(listed))
	}
	// The probes are not counted as requests or connections again.
	if int(rep.Requests) != conns {
		t.Errorf("the summary says %d requests, the ledger holds %d connections", rep.Requests, conns)
	}
	var note string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "ledger: ") && strings.Contains(n, "recorded in") {
			note = n
		}
	}
	if conns != 1 || probes != 1 {
		t.Fatalf("%d connections and %d probes: the lab changed", conns, probes)
	}
	want := "1 to targets (0 requests, 1 connection, and 1 probe sent on those connections, not counted again)"
	if !strings.Contains(note, want) {
		t.Errorf("the ledger note lacks %q: %q", want, note)
	}
	// ledger -summary lists the methods the server saw.
	out, _, _ := cli(t, "ledger", "-summary", led, "-json")
	var sum struct {
		Methods map[string]int `json:"methods"`
		Kinds   map[string]int `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Kinds[ledger.KindProbe] != probes || sum.Methods["HEAD"] == 0 {
		t.Errorf("summary kinds %v methods %v", sum.Kinds, sum.Methods)
	}
}
