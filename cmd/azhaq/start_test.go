package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/docs"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// docs/START.md is the page `azhaq docs start` prints: at most 800 words, its
// commands run, and the README and `azhaq quickstart` lead to it.

const startMaxWords = 800

func startPage(t *testing.T) string {
	t.Helper()
	raw, err := docs.Files.ReadFile("START.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestStartPageIsPrintedAndHoldsItsWords(t *testing.T) {
	out, err := captureStdout(t, func() error { return cmdDocs([]string{"start"}) })
	if err != nil {
		t.Fatal(err)
	}
	if out != startPage(t) {
		t.Errorf("azhaq docs start does not print docs/START.md")
	}
	if n := len(strings.Fields(out)); n > startMaxWords {
		t.Errorf("the start page is %d words, at most %d", n, startMaxWords)
	}
	jobs := regexp.MustCompile(`(?m)^## \d\. (.+)$`).FindAllStringSubmatch(out, -1)
	var got []string
	for _, j := range jobs {
		got = append(got, j[1])
	}
	want := []string{"Make a first map", "Compare two sessions", "Verify a service", "Hand over findings"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("the jobs are %q, want %q in order", got, want)
	}
	if n := strings.Count(out, "\nNext: ["); n != len(want) {
		t.Errorf("%d links onward, want one for each of the %d jobs", n, len(want))
	}
	for _, l := range regexp.MustCompile(`\]\((RECIPES|CONCEPTS)\.md#([^)]+)\)`).FindAllStringSubmatch(out, -1) {
		page, err := docs.Files.ReadFile(l[1] + ".md")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, h := range regexp.MustCompile(`(?m)^#+ (.+)$`).FindAllStringSubmatch(string(page), -1) {
			a := regexp.MustCompile("[^a-z0-9 _-]").ReplaceAllString(strings.ToLower(h[1]), "")
			found = found || strings.ReplaceAll(a, " ", "-") == l[2]
		}
		if !found {
			t.Errorf("the start page links to %s.md#%s, which is no heading", l[1], l[2])
		}
	}
}

// startShop is a small app with two accounts (the bearer tokens ta and tb),
// whose Server header names a version.
func startShop(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		who := map[string]string{"Bearer ta": "alice", "Bearer tb": "bob"}[r.Header.Get("Authorization")]
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<title>shop</title><a href="/api/me">me</a> <a href="/api/books/1">book</a>`)
		case who == "":
			http.Error(w, `{"error":"sign in"}`, http.StatusUnauthorized)
		case r.URL.Path == "/api/me":
			json.NewEncoder(w).Encode(map[string]string{"user": who})
		case r.URL.Path == "/api/books/1":
			json.NewEncoder(w).Encode(map[string]any{"id": 1, "owner": "alice"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startLine splits a command line of the page into its words: double and
// single quotes group, and "> FILE" is the file stdout is written to.
func startLine(line string) (args []string, redirect string) {
	var cur strings.Builder
	var quote byte
	has := false
	flush := func() {
		if has {
			args = append(args, cur.String())
		}
		cur.Reset()
		has = false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote, has = c, true
		case c == ' ':
			flush()
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	flush()
	if n := len(args); n >= 2 && args[n-2] == ">" {
		redirect, args = args[n-1], args[:n-2]
	}
	return args, redirect
}

// startRunToFile runs a command with stdout in the file, as the shell does for
// "> FILE": a page of output may be larger than a pipe holds.
func startRunToFile(t *testing.T, file string, args []string) (stderr string, code int) {
	t.Helper()
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	e, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, e
	err = run(args)
	reportError(args, err)
	os.Stdout, os.Stderr = oldOut, oldErr
	f.Close()
	raw, _ := os.ReadFile(e.Name())
	e.Close()
	return string(raw), exitCode(err)
}

// Every command of the page runs against a stand-in for app.example.com, in
// the order the page gives them, and exits with the code the page says. Three
// things stand in for what the reader has: the host, the tokens and the
// advisory file; -rate and the port list are made quick and local.
func TestStartPageCommandsRun(t *testing.T) {
	useBuiltinIndex(t)
	shop := startShop(t)
	u, _ := url.Parse(shop.URL)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("osv.json", []byte(`[{"id":"CVE-TEST-0001","summary":"old nginx issue",
	  "affected":[{"package":{"name":"nginx","ecosystem":"test"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
	  "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0001"}]}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	stand := strings.NewReplacer("https://app.example.com", shop.URL, "app.example.com", "127.0.0.1", "$TA", "ta", "$TB", "tb",
		"-rate 5", "-rate 500", "-ports top-100", "-ports "+u.Port())
	var ran []string
	in, fenced := false, false
	for _, l := range strings.Split(startPage(t), "\n") {
		if strings.HasPrefix(l, "## ") {
			in = true
		}
		if strings.HasPrefix(l, "```") {
			fenced = !fenced
			continue
		}
		if !in || !fenced || !strings.HasPrefix(l, "azhaq ") {
			continue
		}
		args, redirect := startLine(stand.Replace(l))
		egress.Reset()
		var out, errOut string
		var code int
		if redirect == "" {
			out, errOut, code = cli(t, args[1:]...)
		} else {
			errOut, code = startRunToFile(t, redirect, args[1:])
		}
		egress.Reset()
		if code != exitOK {
			t.Fatalf("%s: exit %d, the page says 0\n%s", l, code, errOut)
		}
		ran = append(ran, l)
		// What the page says to look at is there.
		for cmd, wants := range map[string][]string{
			"azhaq run -url https://app.example.com/ -allow app.example.com -max-requests": {"azhaq run: ", "map rows", "note: ledger: "},
			"azhaq roles -dir": {"azhaq roles: ", "endpoints listed"},
			"azhaq roles show": {"curl"},
			"azhaq run -url https://app.example.com/ -ports top-100 -allow":              {"advisory: nginx 1.18.0", "note: advisories: "},
			"azhaq run -url https://app.example.com/ -ports top-100 -advisories-confirm": {"advisory: nginx 1.18.0", "advisory records of osv.json", "note: advisories: "},
			"azhaq ledger -verify": {"the chain is intact and sealed"},
		} {
			if !strings.HasPrefix(l, cmd) {
				continue
			}
			for _, want := range wants {
				if !strings.Contains(out+errOut, want) {
					t.Errorf("%s: no %q in what it printed\n%s\n%s", l, want, out, errOut)
				}
			}
		}
	}
	if len(ran) != 11 {
		t.Errorf("the page has %d commands, the test ran %d: %q", 11, len(ran), ran)
	}
	for _, f := range []string{"app.db", "app.html", "sent.csv", "roles1/roles.db"} {
		if st, err := os.Stat(f); err != nil || st.Size() == 0 {
			t.Errorf("%s was not written by the page's commands: %v", f, err)
		}
	}
	// sent.csv has a row for each line of the ledger, and the page is HTML
	// that names the target.
	lines := 0
	if err := ledger.Read("app.db.ledger.jsonl", func(ledger.Entry) error { lines++; return nil }); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile("sent.csv"); strings.Count(string(raw), "\n") != lines+1 {
		t.Errorf("sent.csv has %d lines, want one for each of the %d ledger lines and a header", strings.Count(string(raw), "\n"), lines)
	}
	if raw, _ := os.ReadFile("app.html"); !strings.Contains(string(raw), "<html") || !strings.Contains(string(raw), shop.URL) {
		t.Errorf("app.html is not an HTML page that names %s", shop.URL)
	}
	page := startPage(t)
	for _, phrase := range []string{"azhaq run: N map rows", "note: ledger:", "azhaq roles: N endpoints listed", "advisory:", "note: advisories:", "the chain is intact and sealed"} {
		if !strings.Contains(page, phrase) {
			t.Errorf("the page does not name %q", phrase)
		}
	}
}

// The README leads to the page in its first screen.
func TestREADMELinksTheStartPageInItsFirstScreen(t *testing.T) {
	lines := strings.Split(readDoc(t, "../../README.md"), "\n")
	for i, l := range lines {
		if strings.Contains(l, "docs/START.md") {
			if i >= 40 {
				t.Errorf("the README links docs/START.md on line %d, past its first screen", i+1)
			}
			return
		}
	}
	t.Error("the README does not link docs/START.md")
}

// The last line of a first map's summary names the page.
func TestQuickstartLastLineNamesTheStartPage(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>t</title><body>hi</body></html>`)
	}))
	defer site.Close()
	for _, dbName := range []string{"q.db", ""} {
		args := []string{"quickstart", site.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-json", "-no-paths", "-no-tech", "-depth", "0", "-ledger", "off"}
		if dbName != "" {
			args = append(args, "-db", filepath.Join(t.TempDir(), dbName))
		}
		_, errOut, code := cli(t, args...)
		if code != exitOK {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		next, _ := sumMap(t, errOut)["next"].([]any)
		if len(next) == 0 || !strings.HasPrefix(next[len(next)-1].(string), "azhaq docs start ") {
			t.Errorf("db %q: the last line of next is not azhaq docs start: %v", dbName, next)
		}
	}
	_, errOut, code := cli(t, "quickstart", site.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-depth", "0", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "t.db"))
	lines := strings.Split(strings.TrimSpace(errOut), "\n")
	if code != exitOK || !strings.Contains(lines[len(lines)-1], "azhaq docs start") {
		t.Errorf("exit %d, the last line of the summary on the terminal does not name azhaq docs start:\n%s", code, errOut)
	}
}
