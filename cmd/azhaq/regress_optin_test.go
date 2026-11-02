package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The docs say which flag opts a body method in: `params -X` is the opt-in
// itself (no -params-writes), `run -params-method` needs -params-writes.
// Both are pinned here by what a server counts.
func TestBodyMethodOptInIsWhatTheDocsSay(t *testing.T) {
	var posts, gets atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		} else {
			gets.Add(1)
		}
		fmt.Fprint(w, "<html>search</html>")
	}))
	defer srv.Close()
	words := wlist(t, "q", "page", "id")
	for _, m := range []string{"POST", "JSON", "XML"} {
		posts.Store(0)
		_, errOut, code := cli(t, "params", "-u", srv.URL+"/search", "-w", words, "-X", m, "-json")
		if code == exitUsage || posts.Load() == 0 {
			t.Errorf("params -X %s without -params-writes: exit %d, %d POSTs sent\n%s", m, code, posts.Load(), errOut)
		}
	}
	posts.Store(0)
	for file, want := range map[string]string{"CONCEPTS.md": "`params -X POST|JSON|XML`", "ARCHITECTURE.md": "`-X` is the opt-in", "commands/params.md": "`-X` is the opt-in"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", file))
		if err != nil || !strings.Contains(string(raw), want) {
			t.Errorf("docs/%s does not say %s opts a body method in: %v", file, want, err)
		}
	}
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-params", words, "-params-method", "POST", "-db", filepath.Join(t.TempDir(), "r.db"), "-json")
	if code != exitUsage || !strings.Contains(errOut, "-params-writes") || posts.Load() != 0 {
		t.Errorf("run -params-method POST without -params-writes: exit %d, %d POSTs sent\n%s", code, posts.Load(), errOut)
	}
}
