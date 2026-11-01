package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// archiveStandIn serves n distinct archived URLs of lab7stand.org from a
// Wayback-shaped address, 4,000 a page; the graph keeps 200 of them.
func archiveStandIn(t *testing.T, n int) (flag string, urls []string) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	word := func() string {
		b := make([]byte, 8)
		for i := range b {
			b[i] = byte('a' + rng.Intn(26))
		}
		return string(b)
	}
	for i := 0; i < n; i++ {
		urls = append(urls, fmt.Sprintf("http://lab7stand.org/%s/%s.php", word(), word()))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p int
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &p)
		rows := [][]string{{"original"}}
		for i := p * 4000; i < min(n, (p+1)*4000); i++ {
			rows = append(rows, []string{urls[i]})
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	return "wayback=" + srv.URL + "/cdx", urls
}

// runToFile runs a command and returns its stdout and stderr, both read
// while it runs: 12,000 lines do not fit the pipe captureStdout reads only
// after the command ends.
func runToFile(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var bufs [2]bytes.Buffer
	var pipes [2]*os.File
	var done sync.WaitGroup
	olds := [2]*os.File{os.Stdout, os.Stderr}
	for i := range pipes {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		pipes[i] = w
		done.Add(1)
		go func() {
			defer done.Done()
			_, _ = io.Copy(&bufs[i], r)
		}()
	}
	os.Stdout, os.Stderr = pipes[0], pipes[1]
	err := run(args)
	os.Stdout, os.Stderr = olds[0], olds[1]
	pipes[0].Close()
	pipes[1].Close()
	done.Wait()
	return bufs[0].String(), bufs[1].String(), err
}

// export -format urls writes every URL the archives gave, not the 200
// template examples the graph holds; query lists the graph's rows and says
// so; a run that is resumed adds to the list, it does not write it again.
func TestExportURLsWritesEveryArchivedURL(t *testing.T) {
	flag, want := archiveStandIn(t, 12000)
	db := filepath.Join(t.TempDir(), "t.db")
	out, _, err := runToFile(t, "urls", "-d", "lab7stand.org", "-providers", "wayback", "-archive", flag, "-urls-pause", "0", "-silent", "-db", db)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(out)); got != 12000 {
		t.Fatalf("urls printed %d", got)
	}
	exported, errOut, err := runToFile(t, "export", "-db", db, "-format", "urls")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	lines := strings.Fields(exported)
	for _, u := range lines {
		got[u] = true
	}
	if len(lines) != 12000 || len(got) != 12000 {
		t.Fatalf("export wrote %d lines, %d distinct, want 12000", len(lines), len(got))
	}
	for _, u := range want {
		if !got[u] {
			t.Fatalf("export lacks %s", u)
		}
	}
	if strings.Contains(errOut, "template examples") {
		t.Errorf("export writes everything and still says it holds examples: %q", errOut)
	}
	_, errOut, err = captureBoth(t, func() error { return run([]string{"query", "-db", db, "-type", "URL", "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, note := range []string{"the graph holds 200 template examples of the 12000 archived URLs", "query lists the graph's rows", "export -format urls"} {
		if !strings.Contains(errOut, note) {
			t.Errorf("query summary lacks %q: %q", note, errOut)
		}
	}
	if _, err := os.Stat(db + ".urls.jsonl"); err != nil {
		t.Errorf("no list beside the workspace: %v", err)
	}
}

// A workspace made before the list was kept still says what it holds.
func TestExportURLsOfAnOlderWorkspaceSaysWhatItHolds(t *testing.T) {
	flag, _ := archiveStandIn(t, 900)
	db := filepath.Join(t.TempDir(), "t.db")
	if _, _, err := runToFile(t, "urls", "-d", "lab7stand.org", "-providers", "wayback", "-archive", flag, "-urls-pause", "0", "-silent", "-db", db); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(db + ".urls.jsonl"); err != nil {
		t.Fatal(err)
	}
	exported, errOut, err := captureBoth(t, func() error { return run([]string{"export", "-db", db, "-format", "urls"}) })
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(exported)) != 200 || !strings.Contains(errOut, "holds 200 template examples of the 900 archived URLs") || !strings.Contains(errOut, "no list of the rest") {
		t.Errorf("%d lines, stderr %q", len(strings.Fields(exported)), errOut)
	}
}
