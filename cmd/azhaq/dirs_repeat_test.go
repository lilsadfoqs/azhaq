package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// ffuf prints one result for each input that matched, with its position
// (from 1): a blank line twice or a word twice is two rows, as it asked
// twice. The workspace keeps one entity for each URL, and the summary says
// how many inputs were repeats.
func TestDirsListsEachRepeatedInputAsFfufDoes(t *testing.T) {
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		switch r.URL.Path {
		case "/", "/admin", "/dup":
			fmt.Fprint(w, "hello world")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	// ffuf v2.1.0 on this list prints positions 1 and 5 for "/", 3 and 4 for dup.
	wl := wlist(t, "", "admin", "dup", "dup", "", "x1")
	db := t.TempDir() + "/d.db"
	out, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "200", "-json", "-ledger", "off", "-db", db})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	got := map[string]bool{}
	rows := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var row struct {
			URL      string `json:"url"`
			Position int    `json:"position"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			t.Fatalf("row %q", line)
		}
		rows++
		got[fmt.Sprintf("%s %d", strings.TrimPrefix(row.URL, srv.URL), row.Position)] = true
	}
	for _, want := range []string{"/ 1", "/admin 2", "/dup 3", "/dup 4", "/ 5"} {
		if !got[want] {
			t.Errorf("missing row %q in %v", want, got)
		}
	}
	rep := lastReport(t, errOut)
	if rows != 5 || rep.Results != 5 {
		t.Errorf("%d rows, results %d, want 5 as ffuf lists", rows, rep.Results)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "2 inputs of the wordlist repeat an earlier input") {
		t.Errorf("notes %q", rep.Notes)
	}
	if n := asked.Load(); n < 6 {
		t.Errorf("%d requests, each input is asked", n)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ents, _ := st.Entities()
	urls := map[string]int{}
	for _, e := range ents {
		if e.Type == types.TypeURL {
			urls[strings.TrimPrefix(e.Key, srv.URL)]++
		}
	}
	for _, p := range []string{"/", "/dup", "/admin"} {
		if urls[p] != 1 && urls[strings.TrimSuffix(p, "/")] != 1 {
			t.Errorf("the workspace holds one entity of %s: %v", p, urls)
		}
	}
	// Text mode lists them too.
	text, _, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", wl, "-mc", "200", "-ledger", "off"})
	})
	if err != nil || strings.Count(text, srv.URL+"/dup ") != 2 {
		t.Errorf("text rows: %v\n%s", err, text)
	}
}

// The rows an earlier run printed are not printed again by azhaq resume,
// whether or not that run recorded positions; a second hit of one URL at
// another position is a row of its own.
func TestDirsSinkPrintsEachPositionOnce(t *testing.T) {
	d := &dirsSink{printed: map[string]bool{}}
	d.printed[printedKey("http://h/a", 0)] = true // an earlier run's row with no position
	d.printed[printedKey("http://h/b", 3)] = true
	cases := []struct {
		u    string
		pos  int
		want bool
	}{{"http://h/a", 2, false}, {"http://h/b", 3, false}, {"http://h/b", 4, true}, {"http://h/b", 4, false}, {"http://h/c", 1, true}}
	for _, c := range cases {
		if got := d.first(c.u, c.pos); got != c.want {
			t.Errorf("first(%s, %d) = %v, want %v", c.u, c.pos, got, c.want)
		}
	}
}
