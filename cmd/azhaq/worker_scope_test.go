package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A worker takes tasks of a run with -allow naming one host: no row the run
// stores for them names the host's parent domain, outside the scope; a scope
// that holds the domain keeps its row.
func TestWorkerRowsHeldToTheRunsScope(t *testing.T) {
	for _, c := range []struct {
		allow string
		want  []string
	}{{"www.example.test", nil}, {"example.test", []string{`{"key":"example.test"}`}}} {
		t.Run(c.allow, func(t *testing.T) { workerDomainRows(t, c.allow, c.want) })
	}
}

func workerDomainRows(t *testing.T, allow string, want []string) {
	zone := serveZone(t, fakeZone{a: map[string]string{"www.example.test": "127.0.0.1"}})
	joined := make(chan struct{})
	var once sync.Once
	var list []string
	for i := 0; i < 4; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			<-joined
			time.Sleep(400 * time.Millisecond) // the run's own slot is busy; the worker takes the others
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>home</title>`)
		}))
		t.Cleanup(srv.Close)
		list = append(list, "http://www.example.test:"+srvPort(t, srv)+"/")
	}
	file := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(file, []byte(strings.Join(list, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "w.db")
	runErr, workerErr, code := serveWithWorkerJoined(t, func() { once.Do(func() { close(joined) }) },
		"-list", file, "-resolvers", zone, "-allow", allow, "-allow", "127.0.0.1", "-sources", "none", "-db", db)
	if code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, workerErr, runErr)
	}
	if n := tasksDoneHere(workerErr); n < 1 {
		t.Fatalf("the worker ran %d tasks: the test shows nothing\n%s\n%s", n, workerErr, runErr)
	}
	q, _, _ := runContract(t, "query", "-db", db, "-type", "Domain", "-fields", "key")
	if got := lines(q); !slices.Equal(got, want) {
		t.Errorf("-allow %s: Domain rows %q, want %q", allow, got, want)
	}
}
