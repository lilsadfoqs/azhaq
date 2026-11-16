package main

import (
	"bufio"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// odSite answers /admin with a listing, /boom with a 500 page and /big with
// a body past the cap; any other path is a 404.
func odSite(t *testing.T) *httptest.Server {
	t.Helper()
	big := strings.Repeat("a", fuzz.MaxBody+100_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			fmt.Fprint(w, "Index of /admin: secret-listing.txt")
		case "/boom":
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "panic: boom at handler.go:42")
		case "/big":
			fmt.Fprint(w, big)
		case "/":
			fmt.Fprint(w, "front page")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// odFiles are the files of an -od directory, by name.
func odFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = raw
	}
	return out
}

// checkODFiles holds what dirs -od and run -dirs-od both keep: the answer of
// each matched path and of no other, one file each, named by the hash of its
// text, with the body cut at fuzz's cap and the row naming its file.
func checkODFiles(t *testing.T, dir string, rows map[string]string) {
	t.Helper()
	files := odFiles(t, dir)
	if len(files) != 3 || len(rows) != 3 {
		t.Fatalf("%d files for %d matched paths, want 3 of /admin, /boom and /big: files %v, rows %v", len(files), len(rows), files, rows)
	}
	for path, name := range rows {
		text, ok := files[name]
		if !ok {
			t.Errorf("%s: the row names %q, which is not in %s", path, name, dir)
			continue
		}
		if fmt.Sprintf("%x", md5.Sum(text)) != name {
			t.Errorf("%s: the file is not named by the md5 of its text", path)
		}
		if !strings.Contains(string(text), "GET "+path+" HTTP/1.1") || !strings.Contains(string(text), "---- ↑ Request ---- Response ↓ ----") {
			t.Errorf("%s: the file lacks the request: %.200s", path, text)
		}
		switch path {
		case "/admin":
			if !strings.Contains(string(text), "HTTP/1.1 200 OK") || !strings.Contains(string(text), "Index of /admin: secret-listing.txt") {
				t.Errorf("/admin: the file lacks the answer: %.300s", text)
			}
		case "/boom":
			if !strings.Contains(string(text), "HTTP/1.1 500 Internal Server Error") || !strings.Contains(string(text), "panic: boom at handler.go:42") {
				t.Errorf("/boom: the file lacks the 500 page: %.300s", text)
			}
		case "/big":
			if n := len(text); n < fuzz.MaxBody || n > fuzz.MaxBody+4096 {
				t.Errorf("/big: the file is %d bytes, want the headers and %d bytes of body", n, fuzz.MaxBody)
			}
		}
	}
}

// dirs -od keeps the answer of the paths that matched, under fuzz's cap, and
// each row names its file.
func TestDirsODKeepsTheAnswerOfMatchedPathsOnly(t *testing.T) {
	srv := odSite(t)
	dir := filepath.Join(t.TempDir(), "od")
	out, errOut, code := cli(t, "dirs", "-u", srv.URL+"/", "-w", wlist(t, "admin", "boom", "big", "missing", "nothing"), "-od", dir, "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	rows := map[string]string{}
	var cut []string
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var r map[string]any
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		u, _ := r["url"].(string)
		name, _ := r["resultfile"].(string)
		if name == "" {
			t.Errorf("a matched row names no file: %s", sc.Text())
		}
		rows[strings.TrimPrefix(u, srv.URL)] = name
		if r["resultfile_cut"] == true {
			cut = append(cut, u)
		}
	}
	checkODFiles(t, dir, rows)
	if len(cut) != 1 || !strings.HasSuffix(cut[0], "/big") {
		t.Errorf("rows marked cut at the cap: %v, want /big alone", cut)
	}
	// The text line names the file too.
	text, _, _ := cli(t, "dirs", "-u", srv.URL+"/", "-w", wlist(t, "admin"), "-od", dir)
	if !strings.Contains(text, "Resultfile: ") {
		t.Errorf("the text line does not name the file: %q", text)
	}
}

// Without -od no file is written and no row names one.
func TestDirsWithoutODKeepsNothing(t *testing.T) {
	srv := odSite(t)
	out, _, _ := cli(t, "dirs", "-u", srv.URL+"/", "-w", wlist(t, "admin"), "-json")
	if strings.Contains(out, "resultfile") {
		t.Errorf("a row names a file with no -od: %s", out)
	}
}

// run -dirs-od keeps the same files, and the workspace row of each matched
// path names its file.
func TestRunDirsODKeepsTheAnswerOfMatchedPathsOnly(t *testing.T) {
	srv := odSite(t)
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "od")
	db := filepath.Join(tmp, "w.db")
	_, errOut, _ := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-no-tech", "-db", db,
		"-dirs", wlist(t, "admin", "boom", "big", "missing", "nothing"), "-dirs-od", dir, "-quiet", "-ledger", "off")
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, o := range obs {
		if o.Collector != "azhaq-dirs" || o.Kind != "url" {
			continue
		}
		p := payloadOf(types.Observation{Payload: o.Payload})
		u, _ := p["url"].(string)
		name, _ := p["resultfile"].(string)
		rows[strings.TrimPrefix(u, srv.URL)] = name
	}
	checkODFiles(t, dir, rows)
}

// A directory a file cannot be written in is a count in the summary, not a
// stop, and the match has no resultfile.
func TestDirsODCountsAFileItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	srv := odSite(t)
	dir := filepath.Join(t.TempDir(), "od")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	out, errOut, _ := cli(t, "dirs", "-u", srv.URL+"/", "-w", wlist(t, "admin"), "-od", dir, "-json")
	if strings.Contains(out, "resultfile") || !strings.Contains(out, "/admin") {
		t.Errorf("the match should be listed with no resultfile: %s", out)
	}
	if !strings.Contains(errOut, "-od: 1 matches could not be written to "+dir) {
		t.Errorf("the summary does not count the file:\n%s", errOut)
	}
}
