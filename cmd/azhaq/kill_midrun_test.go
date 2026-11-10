package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// A kill file made while paced work waits stops the run with the limit
// exit: what the server got is what the summary and the ledger hold, and a
// request the kill refused before it left is neither listed nor counted.
func TestKillFileMidRunListsOnlyWhatLeft(t *testing.T) {
	dir := t.TempDir()
	kill := filepath.Join(dir, "kill")
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got.Add(1) == 3 {
			_ = os.WriteFile(kill, nil, 0o600)
		}
		w.Header().Set("Connection", "close") // every request dials: the kill is seen at the dial too
		_, _ = w.Write([]byte("page " + r.URL.Path))
	}))
	t.Cleanup(srv.Close)
	words := writeFile(t, dir, "w.txt", strings.Join([]string{"a", "b", "c", "d", "e", "f", "g", "h"}, "\n")+"\n")
	led := filepath.Join(dir, "l.jsonl")
	t.Chdir(dir)
	_, rep, code := runContract(t, "dirs", "-u", srv.URL+"/", "-w", words, "-ac=false", "-mc", "all", "-rate", "4",
		"-kill-file", kill, "-ledger", led, "-db", "k.db")
	lines := 0
	_ = ledger.Read(led, func(e ledger.Entry) error {
		if e.Counted() {
			lines++
		}
		return nil
	})
	if code != exitLimit || int64(got.Load()) != rep.Requests || int64(lines) != rep.Requests {
		t.Errorf("exit %d (want %d); server got %d, summary %d, ledger %d; stopped %q, notes %q",
			code, exitLimit, got.Load(), rep.Requests, lines, rep.Stopped, rep.Notes)
	}
}
