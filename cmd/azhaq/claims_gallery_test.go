package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// runGallery starts the gallery, waits for it to say where it listens, asks
// for its stats from host, stops it with SIGINT and returns what it printed
// on stderr and how it ended.
func runGallery(t *testing.T, host string, args ...string) (stats map[string]any, status int, stderr string, err error) {
	t.Helper()
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	saved := os.Stderr
	os.Stderr = w
	var mu sync.Mutex
	var buf strings.Builder
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		b := make([]byte, 4096)
		for {
			n, e := r.Read(b)
			mu.Lock()
			buf.Write(b[:n])
			mu.Unlock()
			if e != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmdGallery(args) }()
	said := func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
	addr := regexp.MustCompile(`pages of \d+ workspace\(s\) at http://([^/]+)/`)
	var m []string
	for i := 0; i < 400 && m == nil; i++ {
		select {
		case err = <-done:
			os.Stderr = saved
			w.Close()
			<-readDone
			return nil, 0, buf.String(), err
		default:
		}
		m = addr.FindStringSubmatch(said())
		if m == nil {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if m == nil {
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		t.Fatalf("the gallery did not say where it listens: %q", said())
	}
	hostPort := "127.0.0.1:" + m[1][strings.LastIndex(m[1], ":")+1:]
	req, _ := http.NewRequest("GET", "http://"+hostPort+"/api/stats", nil)
	if host != "" {
		req.Host = host
	}
	resp, gerr := http.DefaultClient.Do(req)
	if gerr != nil {
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		t.Fatal(gerr)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	status = resp.StatusCode
	_ = json.Unmarshal(body, &stats)
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the gallery did not stop")
	}
	os.Stderr = saved
	w.Close()
	<-readDone
	return stats, status, buf.String(), err
}

// -workspace takes every *.db file of a directory and of the directories
// directly in it; a database that is not a workspace is skipped with a note,
// one that cannot be read is skipped and the exit code is 3.
func TestGalleryWorkspaceTakesTheDatabasesOfADirectoryAndTheOnesDirectlyInIt(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"one", "one/deeper"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	galleryWorkspace(t, dir, "a")
	galleryWorkspace(t, filepath.Join(dir, "one"), "b")
	galleryWorkspace(t, filepath.Join(dir, "one", "deeper"), "c")
	files, err := workspaceFiles(dir)
	if err != nil || len(files) != 2 || filepath.Base(files[0]) != "a.db" || filepath.Base(files[1]) != "b.db" {
		t.Fatalf("workspaceFiles: %v %v", files, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.db"), nil, 0o644); err != nil { // an empty file: no workspace
		t.Fatal(err)
	}
	stats, _, errOut, err := runGallery(t, "", "-workspace", dir, "-listen", "127.0.0.1:0")
	if err != nil || stats["pages"] != float64(2) || !strings.Contains(errOut, "notes.db: skipped: ") {
		t.Errorf("a database that is not a workspace: %v, stats %v\n%s", err, stats["pages"], errOut)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.db"), []byte("this is not sqlite at all, just text padding padding padding padding"), 0o644); err != nil {
		t.Fatal(err)
	}
	stats, _, errOut, err = runGallery(t, "", "-workspace", dir, "-listen", "127.0.0.1:0")
	if exitCode(err) != exitPartial || stats["pages"] != float64(2) || !strings.Contains(errOut, "broken.db: skipped: ") {
		t.Errorf("a database that cannot be read: exit %d (%v), pages %v\n%s", exitCode(err), err, stats["pages"], errOut)
	}
}

// 127.0.0.1:0 takes any free port, and a loopback gallery answers only
// requests that name a loopback host; bound elsewhere it answers any host and
// says on stderr that anyone who can reach it sees every page.
func TestGalleryListenTakesAFreePortAndAnswersOnlyLoopbackHostsUnlessBoundElsewhere(t *testing.T) {
	dir := t.TempDir()
	db := galleryWorkspace(t, dir, "a")
	stats, status, errOut, err := runGallery(t, "", "-db", db, "-listen", "127.0.0.1:0")
	if err != nil || status != 200 || stats["pages"] != float64(1) || strings.Contains(errOut, "anyone who can reach it") {
		t.Errorf("a free port: %v %d %v\n%s", err, status, stats, errOut)
	}
	if _, status, _, err := runGallery(t, "evil.example:7180", "-db", db, "-listen", "127.0.0.1:0"); err != nil || status != http.StatusForbidden {
		t.Errorf("a request that names another host: %d %v", status, err)
	}
	if _, status, errOut, err := runGallery(t, "gallery.lan:7180", "-db", db, "-listen", "0.0.0.0:0"); err != nil || status != 200 ||
		!strings.Contains(errOut, "anyone who can reach it sees every page, header and console line in the workspace") {
		t.Errorf("bound elsewhere: %d %v\n%s", status, err, errOut)
	}
}
