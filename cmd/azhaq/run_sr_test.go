package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run -sr writes each answer to DIR/HOST/SHA1.txt with an index, as crawl
// does, and query says where a row's is: -ob keeps the body out, no -sr
// stores nothing and leaves the field off.
func TestRunStoresAnswersAndQueryNamesThem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<title>Adminer</title><a href="/settings">settings</a>`)
		case "/settings":
			fmt.Fprint(w, `<title>Settings</title><p>smtp password: hunter2</p>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		name string
		args []string
		body bool
	}{{"body", []string{"-sr"}, true}, {"headers only", []string{"-sr", "-ob"}, false}, {"off", nil, false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			args := append([]string{"run", "-url", srv.URL + "/", "-sources", "none", "-no-paths", "-no-map-guess", "-db", "w.db", "-srd", "saved"}, tc.args...)
			if _, _, code := runContract(t, args...); code != exitOK {
				t.Fatalf("exit %d", code)
			}
			out, _, code := runContract(t, "query", "-db", "w.db", "-type", "URL", "-fields", "key,response_file")
			if code != exitOK {
				t.Fatalf("query exit %d", code)
			}
			found := 0
			for _, r := range jsonRows(t, out) {
				file, _ := r["response_file"].(string)
				if tc.args == nil {
					if file != "" {
						t.Errorf("a row has a stored response with no -sr: %v", r)
					}
					continue
				}
				if !strings.HasSuffix(r["key"].(string), "/settings") {
					continue
				}
				found++
				raw, err := os.ReadFile(file)
				if err != nil || !filepath.IsAbs(file) {
					t.Fatalf("response_file %q: %v", file, err)
				}
				if got := strings.Contains(string(raw), "hunter2"); got != tc.body {
					t.Errorf("body in the stored answer: %v, want %v\n%s", got, tc.body, raw)
				}
				if !strings.Contains(string(raw), "200 OK") || !strings.Contains(string(raw), "Content-Type: text/html") {
					t.Errorf("the stored answer lacks its status line or headers:\n%s", raw)
				}
			}
			if tc.args != nil && found != 1 {
				t.Errorf("%d rows with a stored response for /settings", found)
			}
			if tc.args == nil {
				if _, err := os.Stat("saved"); err == nil {
					t.Error("-srd made a directory with no -sr")
				}
				return
			}
			idx, err := os.ReadFile(filepath.Join("saved", "index.txt"))
			if err != nil || !strings.Contains(string(idx), "/settings") {
				t.Errorf("index: %v\n%s", err, idx)
			}
		})
	}
}
