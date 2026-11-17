package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

// mapSite is a page with a script whose map carries two of the app's own
// files, one without code, and a library's. It counts the requests for the
// map.
func mapSite(t *testing.T, maps *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>x</title></head><body><script src="/a0.js"></script></body></html>`))
		case "/a0.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("fetch('/api/users');\n//# sourceMappingURL=a0.js.map\n"))
		case "/a0.js.map":
			maps.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":3,"sources":["src/app.ts","src/empty.ts","node_modules/lib/x.js"],` +
				`"sourcesContent":["export const key = 'hidden-in-the-map';\nfetch('/api/orders');\n// \u001b[31mred\ttab",null,"module.exports = 1"],"mappings":"AAAA"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runMapSite(t *testing.T, srv *httptest.Server, extra ...string) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "w.db")
	args := append([]string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-no-favicon", "-no-tech", "-db", db, "-quiet", "-ledger", "off"}, extra...)
	if _, errOut, code := cli(t, args...); code != exitOK {
		t.Fatalf("run exit %d\n%s", code, errOut)
	}
	return db
}

// show lists what a source map the run read said: its status, every source
// with whether the map carries its code, and with -body the code itself. The
// map is asked once, and hunt's next step is a command that prints it.
func TestShowListsTheSourceMapTheRunRead(t *testing.T) {
	var maps atomic.Int64
	srv := mapSite(t, &maps)
	db := runMapSite(t, srv)
	if n := maps.Load(); n != 1 {
		t.Errorf("the map was asked %d times by the run", n)
	}
	key := srv.URL + "/a0.js.map"
	out, _, code := cli(t, "show", "-db", db, key)
	if code != exitOK {
		t.Fatalf("show exit %d", code)
	}
	for _, want := range []string{"source map: status 200, 3 sources (1 of a library), 1 of the app's own with their code", "src/app.ts  code, ", "src/empty.ts  no code", "node_modules/lib/x.js  code, 18 bytes  [library]", "show -body prints it"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hidden-in-the-map") {
		t.Errorf("show prints the code without -body:\n%s", out)
	}
	if first, _, _ := strings.Cut(out, "\n"); !strings.Contains(first, "hint") || !strings.Contains(first, "[linked]") {
		t.Errorf("the map's row is not the linked hint: %q", first)
	}
	body, _, _ := cli(t, "show", "-db", db, "-body", key)
	if !strings.Contains(body, "code of src/app.ts") || !strings.Contains(body, "export const key = 'hidden-in-the-map';") || !strings.Contains(body, "    fetch('/api/orders');") {
		t.Errorf("show -body lacks the code:\n%s", body)
	}
	// An escape byte in a target's code never reaches the terminal as it came.
	if strings.Contains(body, "\x1b") || !strings.Contains(body, `\x1b[31mred\ttab`) {
		t.Errorf("show -body does not escape the code:\n%q", body)
	}
	if strings.Contains(body, "module.exports") {
		t.Errorf("a library's code is kept:\n%s", body)
	}
	// -json: the payload's code is shown only with -body.
	for _, with := range []bool{false, true} {
		args := []string{"show", "-db", db, "-json", key}
		if with {
			args = []string{"show", "-db", db, "-json", "-body", key}
		}
		raw, _, _ := cli(t, args...)
		var sh struct {
			Observations []struct {
				Kind    string         `json:"kind"`
				Payload map[string]any `json:"payload"`
			} `json:"observations"`
		}
		if err := json.Unmarshal([]byte(raw), &sh); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, o := range sh.Observations {
			if o.Kind != "sourcemap" {
				continue
			}
			found = true
			if _, has := o.Payload["contents"]; has != with {
				t.Errorf("-body %v: contents in the payload: %v", with, has)
			}
			if o.Payload["status"] != float64(200) || len(o.Payload["source_files"].([]any)) != 3 {
				t.Errorf("payload %v", o.Payload)
			}
		}
		if !found {
			t.Errorf("no sourcemap observation for the map: %s", raw)
		}
	}
	// hunt names the command that works on the stored row.
	hunt, _, _ := cli(t, "hunt", "-db", db)
	if !strings.Contains(hunt, "next: azhaq show -db "+db+" -body "+key) && !strings.Contains(hunt, "→ next: azhaq show -db "+db+" -body "+key) {
		t.Errorf("hunt's next step is not show -body:\n%s", hunt)
	}
	if maps.Load() != 1 {
		t.Errorf("show or hunt asked the map again: %d requests", maps.Load())
	}
}

// With -sr the answer of the map is written whole, and the map's row names
// the file.
func TestStoreResponsesKeepsTheWholeMap(t *testing.T) {
	var maps atomic.Int64
	srv := mapSite(t, &maps)
	srd := filepath.Join(t.TempDir(), "sr")
	db := runMapSite(t, srv, "-sr", "-srd", srd)
	out, _, _ := cli(t, "query", "-db", db, "-match", "a0.js.map", "-fields", "key,response_file", "-json")
	var row struct {
		File string `json:"response_file"`
	}
	if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(out), "\n")[0]), &row); err != nil || row.File == "" {
		t.Fatalf("the map's row names no file: %v %s", err, out)
	}
	raw, err := os.ReadFile(row.File)
	if err != nil || !strings.Contains(string(raw), "hidden-in-the-map") || !strings.Contains(string(raw), "node_modules/lib/x.js") {
		t.Errorf("the file lacks the map: %v\n%s", err, raw)
	}
}

// A workspace made before the map had a row of its own kept the count and the
// app's own names: show says so, and prints the names.
func TestShowSaysWhatAnOldWorkspaceKeptOfAMap(t *testing.T) {
	p, _ := json.Marshal(map[string]any{"url": "https://a.test/m.js.map", "via": "js", "role": "sourcemap", "sources": 4, "with_code": 2, "files": []string{"src/a.ts", "src/b.ts"}})
	out, _, _ := captureBoth(t, func() error {
		printSourceMap([]types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-js", Kind: "url", Payload: p}}}, true)
		return nil
	})
	if !strings.Contains(out, "source map: 4 sources; this workspace kept the count and the app's own names, not the map's status or code") || !strings.Contains(out, "  src/b.ts") {
		t.Errorf("old workspace: %q", out)
	}
}
