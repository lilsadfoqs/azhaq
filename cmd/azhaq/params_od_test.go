package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// reflectSite reflects q into its page and lays the page out otherwise for
// any value of lang. It counts its requests. A page asked with big= answers
// with a body past the 2 MiB the search reads.
func reflectSite(t *testing.T, requests *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		q := r.URL.Query()
		body := "<html><body>results"
		if v := q.Get("q"); v != "" {
			body += " you searched for: " + v + strings.Repeat(" <li>hit</li>", 5)
		}
		if q.Get("lang") != "" {
			body += " LANG-LAYOUT" + strings.Repeat(" <p>translated</p>", 40)
		}
		if q.Get("big") != "" {
			body += strings.Repeat("x", 2<<20+100_000)
		}
		fmt.Fprint(w, body+"</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

var paramWords = []string{"q", "lang", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10"}

// checkParamFiles holds what params -od and run -params-od both keep: a file
// for each reported name and for no other, with the request that showed it
// and the answer it got, named by the md5 of its text.
func checkParamFiles(t *testing.T, dir string, names []string, files map[string]string) {
	t.Helper()
	got := odFiles(t, dir)
	if len(files) != 2 || len(got) != 2 {
		t.Fatalf("files %v for names %v, in dir: %d files; want one for q and one for lang", files, names, len(got))
	}
	for name, f := range files {
		text, ok := got[f]
		if !ok {
			t.Errorf("%s: the row names %q, which is not in %s", name, f, dir)
			continue
		}
		if fmt.Sprintf("%x", md5.Sum(text)) != f {
			t.Errorf("%s: the file is not named by the md5 of its text", name)
		}
		s := string(text)
		if !strings.HasPrefix(s, "GET /s?") || !strings.Contains(s, "---- ↑ Request ---- Response ↓ ----") || !strings.Contains(s, "HTTP/1.1 200 OK") {
			t.Errorf("%s: the file lacks the request or the status line: %.300s", name, s)
		}
		switch name {
		case "q":
			// The value the page printed is the value the file's request sent.
			req, _, _ := strings.Cut(s, "---- ↑ Request")
			m := regexp.MustCompile(`[?&]q=(az[0-9a-f]{8})`).FindStringSubmatch(req)
			if m == nil || !strings.Contains(s, "you searched for: "+m[1]) {
				t.Errorf("q: the request does not carry the value the answer prints: %.400s", s)
			}
		case "lang":
			line, _, _ := strings.Cut(s, "\n")
			if !strings.Contains(s, "LANG-LAYOUT") || strings.Contains(line, "q=") || !strings.Contains(line, "lang=az") {
				t.Errorf("lang: want the request that asked lang alone and the answer it changed: %.400s", s)
			}
		default:
			t.Errorf("a file for %s, which was not reported", name)
		}
	}
}

// params -od keeps the request and answer that showed each reported name, in
// one file each, and no file for a name that was not reported.
func TestParamsODKeepsTheAnswerOfReportedNamesOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	var n atomic.Int64
	srv := reflectSite(t, &n)
	dir := filepath.Join(t.TempDir(), "od")
	words := wlist(t, paramWords...)
	out, _, code := runContract(t, "params", "-u", srv.URL+"/s", "-w", words, "-rate", "10000", "-od", dir, "-json")
	rows := paramRows(t, out)
	if code != exitOK || len(rows) != 1 {
		t.Fatalf("exit %d: %s", code, out)
	}
	files := map[string]string{}
	for k, v := range rows[0]["resultfile"].(map[string]any) {
		files[k] = v.(string)
	}
	checkParamFiles(t, dir, strs(rows[0]["params"]), files)
	if rows[0]["resultfile_cut"] != nil {
		t.Errorf("a body under the cap is marked cut: %v", rows[0]["resultfile_cut"])
	}
	// The text line names the files.
	text, _, _ := cli(t, "params", "-u", srv.URL+"/s", "-w", words, "-rate", "10000", "-od", dir)
	if !strings.Contains(text, "[Resultfile: ") || !strings.Contains(text, "q=") {
		t.Errorf("the text line does not name the files: %q", text)
	}
	// The same search with and without -od sends the same requests.
	requests := func(extra ...string) int64 {
		n.Store(0)
		args := append([]string{"params", "-u", srv.URL + "/s", "-w", words, "-rate", "10000", "-json"}, extra...)
		if _, _, code := runContract(t, args...); code != exitOK {
			t.Fatalf("%v: exit %d", extra, code)
		}
		return n.Load()
	}
	if plain, kept := requests(), requests("-od", filepath.Join(t.TempDir(), "od2")); plain != kept {
		t.Errorf("requests: %d without -od, %d with it: -od must ask nothing more", plain, kept)
	}
}

// Without -od no file is written and no row names one.
func TestParamsWithoutODKeepsNothing(t *testing.T) {
	t.Chdir(t.TempDir())
	var n atomic.Int64
	srv := reflectSite(t, &n)
	out, _, _ := runContract(t, "params", "-u", srv.URL+"/s", "-w", wlist(t, paramWords...), "-rate", "10000", "-json")
	if strings.Contains(out, "resultfile") {
		t.Errorf("a row names a file with no -od: %s", out)
	}
}

// A body past what the search reads is cut in its file, and the row says so.
func TestParamsODMarksACutBody(t *testing.T) {
	t.Chdir(t.TempDir())
	var n atomic.Int64
	srv := reflectSite(t, &n)
	dir := filepath.Join(t.TempDir(), "od")
	out, _, _ := runContract(t, "params", "-u", srv.URL+"/s?big=1", "-w", wlist(t, "q", "a1", "a2", "a3"), "-rate", "10000", "-od", dir, "-json")
	rows := paramRows(t, out)
	if len(rows) != 1 {
		t.Fatalf("%s", out)
	}
	cut := strs(rows[0]["resultfile_cut"])
	if len(cut) != 1 || cut[0] != "q" {
		t.Errorf("resultfile_cut %v, want q alone: %s", cut, out)
	}
	files := rows[0]["resultfile"].(map[string]any)
	text := odFiles(t, dir)[files["q"].(string)]
	if n := len(text); n < 2<<20 || n > fuzz.MaxBody {
		t.Errorf("the file is %d bytes, want the body as read (2 MiB) and no more than the cap", n)
	}
}

// run -params-od keeps the same files, and the workspace row names them.
func TestRunParamsODKeepsTheAnswerOfReportedNamesOnly(t *testing.T) {
	var n atomic.Int64
	srv := reflectSite(t, &n)
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "od")
	db := filepath.Join(tmp, "w.db")
	// The page asked is /s: it is the one searched.
	_, errOut, _ := cli(t, "run", "-url", srv.URL+"/s", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-favicon", "-no-tech", "-db", db,
		"-params", wlist(t, paramWords...), "-params-rate", "10000", "-params-od", dir, "-quiet", "-ledger", "off")
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, o := range obs {
		if o.Collector != "azhaq-params" || o.Kind != "params" {
			continue
		}
		p := payloadOf(types.Observation{Payload: o.Payload})
		if m, ok := p["resultfile"].(map[string]any); ok {
			for k, v := range m {
				files[k] = v.(string)
			}
		}
	}
	checkParamFiles(t, dir, nil, files)
}

// A directory a file cannot be written in is said in the row's note, not a
// stop, and the name has no resultfile.
func TestParamsODCountsAFileItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	t.Chdir(t.TempDir())
	var n atomic.Int64
	srv := reflectSite(t, &n)
	dir := filepath.Join(t.TempDir(), "od")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	out, errOut, _ := cli(t, "params", "-u", srv.URL+"/s", "-w", wlist(t, "q", "a1", "a2"), "-rate", "10000", "-od", dir, "-json")
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(out), "\n")[0]), &row); err != nil || row["resultfile"] != nil {
		t.Errorf("the name should be listed with no resultfile: %v %s", err, out)
	}
	if !strings.Contains(errOut, "-od: 1 names could not be written to "+dir) {
		t.Errorf("the summary does not say it:\n%s", errOut)
	}
}
