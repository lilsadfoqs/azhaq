package jscol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// mapRows are the sourcemap observations of a page's pass, by map URL.
func mapRows(t *testing.T, col *Collector, raw string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": raw}}, func(o types.Observation) error {
		if o.Kind != MapKind {
			return nil
		}
		var p map[string]any
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			t.Fatal(err)
		}
		out[p["url"].(string)] = p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A map that was read is a row of its own: its status, every source name
// with whether the map carries its code and how many bytes. It is read once.
func TestSourceMapRowKeepsWhatWasRead(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	srv := serve(t, map[string]string{
		"/":        `<!doctype html><script src="/main.js"></script>`,
		"/main.js": "fetch('/api/a')\n//# sourceMappingURL=main.js.map",
		"/main.js.map": `{"version":3,"sources":["webpack://app/./src/main.ts","webpack://app/./src/empty.ts","webpack://app/node_modules/x/index.js"],` +
			`"sourcesContent":["export const a = fetch('/api/hidden')",null,"module.exports = 1"],"mappings":"AAAA"}`,
	}, nil)
	rows := mapRows(t, New(srv.Client()), srv.URL+"/")
	m := rows[srv.URL+"/main.js.map"]
	if m == nil {
		t.Fatalf("no row for the map: %v", rows)
	}
	if m["status"] != float64(200) || m["sources"] != float64(3) || m["with_code"] != float64(1) {
		t.Errorf("status, sources and with_code: %v", m)
	}
	var names []string
	for _, s := range m["source_files"].([]any) {
		f := s.(map[string]any)
		names = append(names, fmt.Sprintf("%s code=%v lib=%v", f["name"], f["code"], f["library"] == true))
	}
	want := []string{
		"webpack://app/./src/main.ts code=true lib=false",
		"webpack://app/./src/empty.ts code=false lib=false",
		"webpack://app/node_modules/x/index.js code=true lib=true",
	}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Errorf("source_files %v, want %v", names, want)
	}
	// The code is not in the row: -sr keeps the whole answer.
	if _, has := m["contents"]; has || strings.Contains(fmt.Sprint(m), "hidden") {
		t.Errorf("the row holds code: %v", m)
	}
	for _, s := range m["source_files"].([]any) {
		if f := s.(map[string]any); f["name"] == "webpack://app/./src/main.ts" && f["bytes"] != float64(len("export const a = fetch('/api/hidden')")) {
			t.Errorf("bytes of the code: %v", f)
		}
	}
	if n := srv.asked("/main.js.map"); n != 1 {
		t.Errorf("the map was asked %d times", n)
	}
}

// A big map costs the row nothing: the code is not stored, only a name and a
// size for each source.
func TestSourceMapRowHoldsNoCodeHoweverBigTheMapIs(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	big := strings.Repeat("a", 3<<20)
	var content []string
	for _, s := range []string{big, big, "small()"} {
		raw, _ := json.Marshal(s)
		content = append(content, string(raw))
	}
	srv := serve(t, map[string]string{
		"/":            `<!doctype html><script src="/main.js"></script>`,
		"/main.js":     "var a=1\n//# sourceMappingURL=main.js.map",
		"/main.js.map": `{"version":3,"sources":["a.ts","b.ts","c.ts"],"sourcesContent":[` + strings.Join(content, ",") + `],"mappings":"AAAA"}`,
	}, nil)
	var size int
	_, err := New(srv.Client()).Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		if o.Kind == MapKind {
			size = len(o.Payload)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 || size > 4096 {
		t.Errorf("the row of a 6 MiB map is %d bytes: it must hold names and sizes only", size)
	}
}

// Every map the run reads has a row of its own, however it found it: a
// comment, a header, or a guess next to the bundle. At most maxMapSources
// names are listed, and the rest are counted.
func TestEverySourceMapReadHasARow(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	var names []string
	for i := 0; i < maxMapSources+7; i++ {
		names = append(names, fmt.Sprintf("%q", fmt.Sprintf("src/f%d.ts", i)))
	}
	mapOf := func(src string) string {
		return `{"version":3,"sources":[` + src + `],"mappings":"AAAA"}`
	}
	srv := serve(t, map[string]string{
		"/":           `<!doctype html><script src="/c.js"></script><script src="/hdr.js"></script><script src="/g.js"></script>`,
		"/c.js":       "var c=1\n//# sourceMappingURL=c.js.map",
		"/c.js.map":   mapOf(strings.Join(names, ",")),
		"/hdr.js":     "var h=1",
		"/maps/h.map": mapOf(`"src/h.ts"`),
		"/g.js":       "var g=1",
		"/g.js.map":   mapOf(`"src/g.ts"`),
	}, map[string]http.Header{"/hdr.js": {"Sourcemap": {"/maps/h.map"}}})
	rows := mapRows(t, New(srv.Client()), srv.URL+"/")
	for _, p := range []string{"/c.js.map", "/maps/h.map", "/g.js.map"} {
		if m := rows[srv.URL+p]; m == nil || m["status"] != float64(200) {
			t.Errorf("no row for %s: %v", p, m)
		}
	}
	c := rows[srv.URL+"/c.js.map"]
	if c == nil {
		return
	}
	if got := len(c["source_files"].([]any)); got != maxMapSources || c["source_files_cut"] != float64(7) || c["sources"] != float64(maxMapSources+7) {
		t.Errorf("%d names listed, cut %v, sources %v", got, c["source_files_cut"], c["sources"])
	}
}
