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

// A command that writes its targets or words to a temporary list stops on a
// limit, and azhaq resume finishes it: the list it reads is the copy kept
// next to the workspace, not the temporary one removed when the command ended.
func TestResumeOfACommandThatStoppedReadsItsKeptInputs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><title>%s</title><a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a></html>`, r.URL.Path)
	}))
	defer srv.Close()
	dir := t.TempDir()
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"params", []string{"params", "-u", srv.URL + "/", "-w", words, "-c", "3", "-max-requests", "8"}},
		{"crawl", []string{"crawl", "-u", srv.URL + "/", "-max-requests", "2"}},
		{"probe", []string{"probe", "-u", srv.URL + "/a", "-u", srv.URL + "/b", "-u", srv.URL + "/c", "-max-requests", "1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "w.db")
			_, errOut, code := cli(t, append(c.args, "-db", db)...)
			if code != exitLimit {
				t.Fatalf("the first run exits %d, want %d (stopped by the limit):\n%s", code, exitLimit, errOut)
			}
			kept, _ := filepath.Glob(db + ".input-*.txt")
			if len(kept) == 0 {
				t.Errorf("no input kept next to the workspace")
			}
			_, errOut, code = cli(t, "resume", "-db", db, "-max-requests", "0")
			if code != exitOK || strings.Contains(errOut, "no such file") {
				t.Errorf("resume exits %d:\n%s", code, errOut)
			}
		})
	}
}

// keepInputs rewrites only the lists tempList wrote, inline or not.
func TestKeepInputsCopiesOnlyTemporaryLists(t *testing.T) {
	list, rm, err := tempList([]string{"http://a.test/"})
	if err != nil {
		t.Fatal(err)
	}
	defer rm()
	db := filepath.Join(t.TempDir(), "w.db")
	got := keepInputs([]string{"-list", list, "-w=" + list, "-u", "/etc/hosts"}, db)
	if !strings.HasPrefix(got[1], db+".input-") || !strings.HasPrefix(got[2], "-w="+db+".input-") || got[4] != "/etc/hosts" {
		t.Fatalf("args %q", got)
	}
	if b, err := os.ReadFile(got[1]); err != nil || string(b) != "http://a.test/\n" {
		t.Errorf("the copy: %q %v", b, err)
	}
}
