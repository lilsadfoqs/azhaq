package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// uriServer answers 200 to everything and keeps each request line's target.
func uriServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.RequestURI)
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := slices.Clone(got)
		slices.Sort(out)
		return out
	}
}

// Two -w on one keyword are one list, a then b: 8 and 3 words are 11 requests,
// where ffuf asks the 24 combinations. The summary says so.
func TestFuzzTwoListsOnOneKeywordAreJoinedAndSaySo(t *testing.T) {
	srv, uris := uriServer(t)
	a := wlist(t, "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8")
	b := wlist(t, "b1", "b2", "b3")
	rows, rep, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", a, "-w", b, "-mode", "clusterbomb")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 11 || rep.Requests != 11 || len(uris()) != 11 {
		t.Errorf("%d results, %d requests counted, %d at the server", len(rows), rep.Requests, len(uris()))
	}
	notes := strings.Join(rep.Notes, "\n")
	for _, want := range []string{"2 wordlists share the keyword FUZZ (8 and 3 words)", "joined into one list of 11 words", "ffuf combines them, 24 requests"} {
		if !strings.Contains(notes, want) {
			t.Errorf("no %q in the notes: %q", want, rep.Notes)
		}
	}
	// A word twice in a list is asked twice.
	srv2, uris2 := uriServer(t)
	if _, _, err := fuzzRows(t, "-u", srv2.URL+"/FUZZ", "-w", wlist(t, "a", "a", "b")); err != nil {
		t.Fatal(err)
	}
	if got := uris2(); !slices.Equal(got, []string{"/a", "/a", "/b"}) {
		t.Errorf("a repeated word asked %q", got)
	}
	// Pitchfork does not claim a count for ffuf; a keyword for each list makes no note.
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", a, "-w", b, "-mode", "pitchfork")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Join(rep.Notes, "\n"); !strings.Contains(n, "joined into one list of 11 words") || strings.Contains(n, "ffuf combines") {
		t.Errorf("pitchfork notes: %q", rep.Notes)
	}
	_, rep, err = fuzzRows(t, "-u", srv.URL+"/FUZZ/W2", "-w", a+":FUZZ", "-w", b+":W2")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Requests != 24 || strings.Contains(strings.Join(rep.Notes, "\n"), "share the keyword") {
		t.Errorf("one keyword each: %d requests, notes %q", rep.Requests, rep.Notes)
	}
}

// A dirs word is always a path: # and a space are percent-encoded and so is
// a %, a ? starts the query as in ffuf. In fuzz the word goes into the URL as
// written: # starts a fragment that is never sent.
func TestDirsWordIsAPathAndFuzzWordIsAsWritten(t *testing.T) {
	words := wlist(t, "#comment-word", "x#y", "a b", "50%", "a%20b", "q?a=1", "c?d e#f")
	srv, uris := uriServer(t)
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-mc", "all", "-ac=false", "-json", "-ledger", "off"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	want := []string{"/%23comment-word", "/50%25", "/a%20b", "/a%2520b", "/c?d%20e%23f", "/q?a=1", "/x%23y"}
	if got := uris(); !slices.Equal(got, want) {
		t.Errorf("dirs asked %q, want %q", got, want)
	}

	srv, uris = uriServer(t)
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-w", wlist(t, "#comment-word", "x#y", "a b", "a%20b", "q?a=1")); err != nil {
		t.Fatal(err)
	}
	want = []string{"/", "/a%20b", "/a%20b", "/q?a=1", "/x"}
	if got := uris(); !slices.Equal(got, want) {
		t.Errorf("fuzz asked %q, want %q", got, want)
	}

	// With FUZZ in the query nothing is encoded or cut: the word is the value.
	srv, uris = uriServer(t)
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/p?q=FUZZ", "-w", wlist(t, "a%20b", "x#y")); err != nil {
		t.Fatal(err)
	}
	if got := uris(); !slices.Equal(got, []string{"/p?q=a%20b", "/p?q=x"}) {
		t.Errorf("fuzz with FUZZ in the query asked %q", got)
	}
}

// -raw sends the word as written: the # stays in the request line.
func TestFuzzRawSendsTheWordAsWritten(t *testing.T) {
	srv, uris := uriServer(t)
	if _, _, err := fuzzRows(t, "-u", srv.URL+"/FUZZ", "-raw", "-w", wlist(t, "#comment-word", "x#y", "q?a=1")); err != nil {
		t.Fatal(err)
	}
	want := []string{"/#comment-word", "/q?a=1", "/x#y"}
	if got := uris(); !slices.Equal(got, want) {
		t.Errorf("-raw asked %q, want %q", got, want)
	}
}
