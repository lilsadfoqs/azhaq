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

// showJSON is show -json of key.
func showJSON(t *testing.T, db, key string, extra ...string) map[string]any {
	t.Helper()
	raw, _, _ := cli(t, append(append([]string{"show", "-db", db, "-json"}, extra...), key)...)
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return out
}

// show lists what a source map the run read said: its status and every
// source with whether the map carries its code. A run without -sr keeps no
// code, and show -body says so in one line. The map is asked once.
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
	for _, want := range []string{"source map: status 200, 3 sources (1 of a library), 1 of the app's own with their code", "src/app.ts  code, ", "src/empty.ts  no code", "node_modules/lib/x.js  code, 18 bytes  [library]"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if first, _, _ := strings.Cut(out, "\n"); !strings.Contains(first, "hint") || !strings.Contains(first, "[linked]") {
		t.Errorf("the map's row is not the linked hint: %q", first)
	}
	body, _, _ := cli(t, "show", "-db", db, "-body", key)
	if !strings.Contains(body, "  the code was not kept: a run with -sr keeps it\n") || strings.Contains(body, "hidden-in-the-map") || strings.Contains(body, "code of ") {
		t.Errorf("show -body without -sr:\n%s", body)
	}
	// No code is in the workspace: not in the payload, not in the file the run wrote.
	for _, with := range []bool{false, true} {
		var extra []string
		if with {
			extra = []string{"-body"}
		}
		sh := showJSON(t, db, key, extra...)
		raw, _ := json.Marshal(sh)
		if strings.Contains(string(raw), "hidden-in-the-map") || sh["source_code"] != nil {
			t.Errorf("-body %v: the code is in the output: %s", with, raw)
		}
		found := false
		for _, o := range sh["observations"].([]any) {
			o := o.(map[string]any)
			if o["kind"] != "sourcemap" {
				continue
			}
			found = true
			p := o["payload"].(map[string]any)
			if p["status"] != float64(200) || len(p["source_files"].([]any)) != 3 {
				t.Errorf("payload %v", p)
			}
		}
		if !found {
			t.Errorf("no sourcemap observation for the map: %s", raw)
		}
	}
	// With no answer kept, hunt's next step is show alone.
	hunt, _, _ := cli(t, "hunt", "-db", db)
	if !strings.Contains(hunt, "next: azhaq show -db "+db+" "+key) || strings.Contains(hunt, "-body "+key) {
		t.Errorf("hunt's next step is not show alone:\n%s", hunt)
	}
	if maps.Load() != 1 {
		t.Errorf("show or hunt asked the map again: %d requests", maps.Load())
	}
}

// With -sr the answer of the map is written whole and the map's row names
// the file. show -body prints the app's own code from it, escaped, and
// hunt's next step has -body.
func TestShowBodyPrintsTheCodeOfAMapStoreResponsesKept(t *testing.T) {
	var maps atomic.Int64
	srv := mapSite(t, &maps)
	srd := filepath.Join(t.TempDir(), "sr")
	db := runMapSite(t, srv, "-sr", "-srd", srd)
	key := srv.URL + "/a0.js.map"
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
	plain, _, _ := cli(t, "show", "-db", db, key)
	if !strings.Contains(plain, "show -body prints the app's own code") || strings.Contains(plain, "hidden-in-the-map") {
		t.Errorf("show:\n%s", plain)
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
		t.Errorf("a library's code is printed:\n%s", body)
	}
	code, _ := json.Marshal(showJSON(t, db, key, "-body")["source_code"])
	if !strings.Contains(string(code), `"name":"src/app.ts"`) || strings.Contains(string(code), "module.exports") {
		t.Errorf("show -json -body source_code: %s", code)
	}
	hunt, _, _ := cli(t, "hunt", "-db", db)
	if !strings.Contains(hunt, "next: azhaq show -db "+db+" -body "+key) {
		t.Errorf("hunt's next step is not show -body:\n%s", hunt)
	}
	// The file gone: one line, not an error.
	if err := os.Remove(row.File); err != nil {
		t.Fatal(err)
	}
	gone, _, code2 := cli(t, "show", "-db", db, "-body", key)
	if code2 != exitOK || !strings.Contains(gone, "the code was not kept") || strings.Contains(gone, "code of ") {
		t.Errorf("show -body with the file gone (exit %d):\n%s", code2, gone)
	}
	if maps.Load() != 1 {
		t.Errorf("the map was asked %d times", maps.Load())
	}
}

// With -sr -ob the file holds no body, and show -body says so.
func TestShowBodySaysAnOmittedBodyHasNoCode(t *testing.T) {
	var maps atomic.Int64
	srv := mapSite(t, &maps)
	db := runMapSite(t, srv, "-sr", "-ob", "-srd", filepath.Join(t.TempDir(), "sr"))
	body, _, _ := cli(t, "show", "-db", db, "-body", srv.URL+"/a0.js.map")
	if !strings.Contains(body, "holds no body (-ob)") || strings.Contains(body, "hidden-in-the-map") {
		t.Errorf("show -body:\n%s", body)
	}
}

// A workspace made before the map had a row of its own kept the count and the
// app's own names: show says so, and prints the names.
func TestShowSaysWhatAnOldWorkspaceKeptOfAMap(t *testing.T) {
	p, _ := json.Marshal(map[string]any{"url": "https://a.test/m.js.map", "via": "js", "role": "sourcemap", "sources": 4, "with_code": 2, "files": []string{"src/a.ts", "src/b.ts"}})
	out, _, _ := captureBoth(t, func() error {
		printSourceMap([]types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-js", Kind: "url", Payload: p}}}, "", true)
		return nil
	})
	if !strings.Contains(out, "source map: 4 sources; this workspace kept the count and the app's own names, not the map's status or code") || !strings.Contains(out, "  src/b.ts") {
		t.Errorf("old workspace: %q", out)
	}
}
