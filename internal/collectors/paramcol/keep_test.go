package paramcol

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/types"
)

// A group whose finds are not reported (the page answers any name, or the
// group is past the one that did) holds no answer, and only the names that
// are reported are remembered.
func TestGatherHoldsNothingForUnreportedGroups(t *testing.T) {
	s := &search{floodAt: 1}
	mk := func(idx int, any bool) *chunk {
		ck := &chunk{idx: idx, found: map[string]string{}, any: any}
		ck.set(fmt.Sprintf("n%d", idx), "size", &exchange{body: make([]byte, 1<<20)})
		return ck
	}
	chunks := []*chunk{mk(0, false), mk(1, true), mk(2, false)}
	found := map[string]string{}
	s.gather("http://x/", chunks, found)
	if len(s.kept) != 1 || s.kept["n0"] == nil {
		t.Errorf("remembered %v, want the exchange of n0 alone", s.kept)
	}
	if chunks[1].ex != nil || chunks[2].ex != nil {
		t.Errorf("a group that is not reported still holds its answers")
	}
}

// With KeepDir, a page that answers any name reports no name and writes no file.
func TestKeepDirWritesNothingForAFloodedPage(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>")
		for k := range r.URL.Query() {
			if !strings.HasPrefix(k, "~") && !strings.HasPrefix(k, "az") {
				fmt.Fprintf(w, "<p>unknown parameter %s</p>\n", html.EscapeString(k))
			}
		}
		fmt.Fprint(w, "</body></html>")
	}))
	defer srv.Close()
	var words []string
	for i := 0; i < 300; i++ {
		words = append(words, fmt.Sprintf("name%d", i))
	}
	dir := t.TempDir()
	c := New(srv.Client(), Options{Words: words, Rate: 10000, KeepDir: dir})
	var got map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &got)
	})
	if err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 || got["resultfile"] != nil {
		t.Errorf("%d files and resultfile %v for a page that reports no name", len(ents), got["resultfile"])
	}
}

// A name the page prints, and a name in the URL that the page reads, are kept
// with the answer that showed them.
func TestKeepDirKeepsNamedAndGivenNames(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		body := "<html><body>catalog"
		if q.Has("category") {
			body += " (filter category applied)"
		}
		if q.Get("page") != "" && q.Get("page") != "1" {
			body += strings.Repeat(" <li>more</li>", 30)
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	defer srv.Close()
	words := []string{"category", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10"}
	dir := t.TempDir()
	c := New(srv.Client(), Options{Words: words, Rate: 10000, KeepDir: dir})
	got := runOn(t, c, srv.URL+"/c?page=1")
	files, _ := got["resultfile"].(map[string]any)
	read := func(name string) string {
		f, _ := files[name].(string)
		raw, err := os.ReadFile(dir + "/" + f)
		if err != nil {
			t.Fatalf("%s: %v in %v", name, err, got)
		}
		return string(raw)
	}
	if s := read("category"); !strings.Contains(s, "filter category applied") {
		t.Errorf("named name: the file lacks the answer that printed it: %.300s", s)
	}
	if s := read("page"); !strings.Contains(s, "more") || !strings.Contains(s, "page=") {
		t.Errorf("name given in the URL: the file lacks the answer that showed it: %.300s", s)
	}
}

// A switch name that answers only to its own value is kept with the request
// that carried that value.
func TestKeepDirKeepsASwitchWithItsValue(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("debug") == "true" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "stack: handler.go:42")
			return
		}
		fmt.Fprint(w, "<html><body>fine</body></html>")
	}))
	defer srv.Close()
	dir := t.TempDir()
	c := New(srv.Client(), Options{Words: []string{"a1", "a2", "a3"}, Rate: 10000, KeepDir: dir})
	got := runOn(t, c, srv.URL+"/")
	files, _ := got["resultfile"].(map[string]any)
	f, _ := files["debug"].(string)
	raw, err := os.ReadFile(dir + "/" + f)
	if err != nil || !strings.Contains(string(raw), "debug=true") || !strings.Contains(string(raw), "HTTP/1.1 500") || !strings.Contains(string(raw), "stack: handler.go:42") {
		t.Errorf("the switch's file: %v\n%s\nrow %v", err, raw, got)
	}
}
