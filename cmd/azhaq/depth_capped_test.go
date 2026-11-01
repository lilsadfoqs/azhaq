package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var depthNote = regexp.MustCompile(`-depth \d+: (\d+) URLs found past it`)

// A URL found more than once past -depth is one URL in the note.
func TestDepthNoteCountsDistinctURLs(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, "<title>home</title><a href='/a'>a</a><a href='/b'>b</a>")
			return
		}
		if r.URL.Path == "/a" || r.URL.Path == "/b" {
			fmt.Fprintf(w, "<title>%s</title><a href='/c'>c</a><a href='/d'>d</a>", r.URL.Path) // both pages link the same two
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, rep, _ := runContract(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-takeover",
		"-no-paths", "-no-favicon", "-no-tech", "-depth", "2", "-db", "d.db")
	for _, n := range rep.Notes {
		if m := depthNote.FindStringSubmatch(n); m != nil {
			if m[1] != "2" {
				t.Errorf("/c and /d are two URLs, found four times: %s", n)
			}
			return
		}
	}
	t.Fatalf("no depth note: %v", rep.Notes)
}

// A dirs sweep names no run depth: the -depth of a sweep is its own, and
// the URLs it found are rows it asked.
func TestDirsSweepHasNoRunDepthNote(t *testing.T) {
	t.Chdir(t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/about", "/admin", "/secret":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<title>x</title>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	words := writeList(t, "about", "admin", "secret", "nope", "x1", "x2")
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"dirs", "-u", srv.URL + "/", "-w", words, "-depth", "2", "-allow", "127.0.0.1", "-db", "dd.db", "-ledger", "off", "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if rep := lastReport(t, errOut); depthNote.MatchString(strings.Join(rep.Notes, "\n")) || strings.Contains(strings.Join(rep.Notes, "\n"), "azhaq resume -depth") {
		t.Errorf("a dirs sweep advises a larger run depth: %v", rep.Notes)
	}
}
