package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// exportDB is a workspace with one URL.
func exportDB(t *testing.T, dir string) string {
	t.Helper()
	db := filepath.Join(dir, "w.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e, err := st.UpsertEntity(types.TypeURL, "http://app.test/", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddObservation(e.ID, types.Observation{Collector: "azhaq-http", Kind: "probe", Payload: json.RawMessage(`{"url":"http://app.test/","status":200}`), ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return db
}

// Without -db the export is of the last run's database, and -format is jsonl
// unless it says otherwise.
func TestExportUsesTheLastRunsDatabaseAndJSONLByDefault(t *testing.T) {
	dir := t.TempDir()
	db := exportDB(t, dir)
	t.Chdir(dir)
	if _, _, err := captureBoth(t, func() error { return cmdExport(nil) }); err == nil || !strings.Contains(err.Error(), "need -db") {
		t.Errorf("with no last run: %v, want an error that asks for -db", err)
	}
	if err := os.WriteFile(lastDBFile, []byte(db+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	byDefault, _, err := captureBoth(t, func() error { return cmdExport(nil) })
	if err != nil {
		t.Fatal(err)
	}
	named, _, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", "jsonl"}) })
	if err != nil || byDefault != named || !strings.Contains(byDefault, `"kind":"entity"`) {
		t.Errorf("by default: %.200q, with -db and -format jsonl: %.200q (%v)", byDefault, named, err)
	}
	urls, _, err := captureBoth(t, func() error { return cmdExport([]string{"-format", "urls"}) })
	if err != nil || strings.TrimSpace(urls) != "http://app.test/" {
		t.Errorf("-format urls without -db: %q %v", urls, err)
	}
}

// A format that finds nothing writes nothing and says why on stderr, exit 0;
// findings and findings-md write an explicit empty set; graphql and sdl, with
// no schema read, are an error that names -graphql.
func TestExportOfAWorkspaceWithNothingToWrite(t *testing.T) {
	db := filepath.Join(t.TempDir(), "empty.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	for _, format := range []string{"names", "hosts", "secrets", "targets"} {
		out, errOut, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", format}) })
		if err != nil || out != "" || !strings.Contains(errOut, "azhaq export: nothing to write: ") {
			t.Errorf("%s: output %q, stderr %q, err %v: want nothing written, the reason on stderr and exit 0", format, out, errOut, err)
		}
	}
	out, _, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", "findings"}) })
	if err != nil || strings.TrimSpace(out) != `{"type":"findings","findings":0,"identifications":0,"leads":0}` {
		t.Errorf("findings: %q %v", out, err)
	}
	out, _, err = captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", "findings-md"}) })
	if err != nil || !strings.Contains(out, "No qualifying rows") || !strings.Contains(out, "0 findings, 0 identifications, 0 leads") {
		t.Errorf("findings-md: %q %v", out, err)
	}
	for _, format := range []string{"graphql", "sdl"} {
		out, _, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", format}) })
		if err == nil || out != "" || exitCode(err) != 1 || !strings.Contains(err.Error(), "no GraphQL schema") || !strings.Contains(err.Error(), "-graphql") {
			t.Errorf("%s: output %q, error %v (exit %d)", format, out, err, exitCode(err))
		}
	}
}

func writePNG(t *testing.T, path string, w, h int) {
	t.Helper()
	im := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			im.Set(x, y, color.RGBA{uint8(x), uint8(y), 90, 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The html export embeds each screenshot 560 pixels wide (a narrower one as it
// is), looks for the file where the run named it and beside the database, and
// lists one it finds in neither as not found: the page holds its pictures, so
// it opens from any directory.
func TestExportHTMLEmbedsScreenshotsAt560AndListsMissingOnes(t *testing.T) {
	dir := t.TempDir()
	beside := filepath.Join(dir, "beside")
	elsewhere := t.TempDir()
	os.MkdirAll(beside, 0o755)
	writePNG(t, filepath.Join(dir, "wide.png"), 1200, 800)       // beside the database, by its name
	writePNG(t, filepath.Join(elsewhere, "named.png"), 300, 200) // where the run named it
	st, err := store.Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	add := func(url, file, abs string) {
		e, err := st.UpsertEntity(types.TypeURL, url, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"url": url, "file": file, "file_path": abs, "phash": "p:0000000000000000"})
		if _, err := st.AddObservation(e.ID, types.Observation{Collector: "azhaq-shots", Kind: "screenshot", Payload: payload, ObservedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	add("http://one.test/", "wide.png", filepath.Join(t.TempDir(), "gone", "wide.png"))
	add("http://two.test/", "named.png", filepath.Join(elsewhere, "named.png"))
	add("http://three.test/", "missing.png", "/nonexistent/missing.png")
	st.Close()
	var out bytes.Buffer
	if err := exportAs(filepath.Join(dir, "w.db"), "html", "", &out); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	widths := []int{}
	for _, m := range regexp.MustCompile(`data:image/jpeg;base64,([^"'\s)]+)`).FindAllStringSubmatch(page, -1) {
		enc, _ := url.QueryUnescape(html.UnescapeString(m[1]))
		raw, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(enc, " ", "+"))
		cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		widths = append(widths, cfg.Width)
	}
	have := map[int]bool{}
	for _, w := range widths {
		have[w] = true
	}
	if len(have) != 2 || !have[560] || !have[300] {
		t.Errorf("embedded widths %v, want only 560 (the wide picture) and 300 (the narrow one as it is)", widths)
	}
	if strings.Count(page, "picture not found: missing.png") != 1 || strings.Contains(page, "picture not found: wide.png") || strings.Contains(page, "picture not found: named.png") {
		t.Errorf("the missing picture is not the only one listed as not found")
	}
	for _, ref := range []string{`src="wide.png"`, `src="/`, `src="file:`, filepath.Join(elsewhere, "named.png")} {
		if strings.Contains(page, ref) {
			t.Errorf("the page refers to a file (%s): it would not open from another directory", ref)
		}
	}
}

// A schema kept by names only gives each operation a type and a name.
func TestOpenAPIGraphQLKeptByNamesGivesTypeAndName(t *testing.T) {
	g := &graphView{path: "x.db", rows: []engine.MapEntry{urlRow("https://api.test/graphql",
		engine.Op{Method: "POST", Body: []string{"query", "variables"}, Source: "js-call"},
		engine.Op{Method: "POST", Summary: "query users", OperationID: "users", Source: "graphql"},
		engine.Op{Method: "POST", Summary: "query ping", OperationID: "ping", Source: "graphql"},
		engine.Op{Method: "POST", Summary: "mutation login", OperationID: "login", Source: "graphql"})}}
	doc, err := openAPI(g, "")
	if err != nil {
		t.Fatal(err)
	}
	post := doc["paths"].(map[string]any)["/graphql"].(map[string]any)["post"].(map[string]any)
	raw, _ := json.Marshal(post["x-azhaq-graphql"])
	var x struct {
		Operations []map[string]any
	}
	if err := json.Unmarshal(raw, &x); err != nil || len(x.Operations) != 3 {
		t.Fatalf("x-azhaq-graphql %s (%v)", raw, err)
	}
	for _, o := range x.Operations {
		if len(o) != 2 || o["type"] == nil || o["name"] == nil {
			t.Errorf("an operation of a schema kept by names has %v, want only type and name", o)
		}
	}
}

// In a recovered schema's SDL, the fields whose type was not recovered and the
// client operations found in scripts are listed in comments.
func TestRecoveredSDLListsUntypedFieldsAndClientOperationsInComments(t *testing.T) {
	var sdl bytes.Buffer
	if err := graphqlExport(recoveredGraph("https://api.test/graphql"), "sdl", "", &sdl); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(sdl.String(), "\n") {
		if (strings.Contains(line, "left out of Query: ping") || strings.Contains(line, "getMe") || strings.Contains(line, "mutation Login")) && !strings.HasPrefix(line, "#") {
			t.Errorf("a line of what was not recovered is not a comment: %q", line)
		}
	}
	for _, want := range []string{"# fields whose type was not recovered, left out of Query: ping", "# client operations seen in scripts: mutation Login, query getMe"} {
		if !strings.Contains(sdl.String(), want) {
			t.Errorf("the SDL lacks %q:\n%s", want, sdl.String())
		}
	}
}

// An API route kept out whose callers do not say the method is described as a
// POST, with x-azhaq.method saying it is a guess; it is never a GET.
func TestOpenAPIKeptOutRouteWithNoCallerIsAGuessedPOST(t *testing.T) {
	r := urlRow("https://app.test/api/user/change-email")
	r.Coverage, r.Status = "skipped", 0
	doc, err := openAPI(&graphView{path: "x.db", rows: []engine.MapEntry{r}}, "")
	if err != nil {
		t.Fatal(err)
	}
	item := doc["paths"].(map[string]any)["/api/user/change-email"].(map[string]any)
	if item["get"] != nil || item["head"] != nil {
		t.Errorf("a kept out route has a GET or HEAD: %v", item)
	}
	post, _ := item["post"].(map[string]any)
	x, _ := post["x-azhaq"].(map[string]any)
	if post == nil || !strings.HasPrefix(fmt.Sprint(x["method"]), "guessed") || post["x-azhaq-skipped"] != true {
		t.Errorf("POST %v, x-azhaq %v: want a guessed POST flagged as not requested", post, x)
	}
}

// Each Burp rule is for any protocol, port and path: an entry holds no port
// and no file.
func TestBurpRulesAreForAnyProtocolPortAndPath(t *testing.T) {
	for _, e := range burpEntries([]string{"example.com", "*.example.org", "=api.example.net", "192.0.2.7", "10.0.0.0/24"}) {
		if len(e) != 3 || e["protocol"] != "any" || e["enabled"] != true || e["host"] == nil {
			t.Errorf("entry %v: want only enabled, protocol any and a host", e)
		}
	}
}

// A run without allow rules lists every web service it found, and so does a run
// whose scope file is gone, which a note on stderr says.
func TestBurpScopeOfARunWithoutRulesOrWithAGoneScopeFile(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, args []string) string {
		db := filepath.Join(dir, name)
		st, err := store.Open(db)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.BeginRun("r1", 1, 100); err != nil {
			t.Fatal(err)
		}
		if err := st.SetRunArgs(args); err != nil {
			t.Fatal(err)
		}
		for _, u := range []string{"https://app.test/", "http://other.test:8080/"} {
			e, err := st.UpsertEntity(types.TypeURL, u, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]any{"url": u, "status": 200, "title": "t"})
			if _, err := st.AddObservation(e.ID, types.Observation{Collector: "azhaq-http", Kind: "application", Payload: payload, ObservedAt: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
		}
		return db
	}
	hosts := func(db string) (string, string) {
		out, errOut, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", "burp"}) })
		if err != nil {
			t.Fatal(err)
		}
		return out, errOut
	}
	out, errOut := hosts(mk("none.db", []string{"-url", "https://app.test/"}))
	if !strings.Contains(out, `"^app\\.test$"`) || !strings.Contains(out, `"^other\\.test$"`) || strings.Contains(errOut, "scope") {
		t.Errorf("a run with no allow rules: %s (stderr %q)", out, errOut)
	}
	out, errOut = hosts(mk("gone.db", []string{"-url", "https://app.test/", "-scope", filepath.Join(dir, "gone-scope.txt")}))
	if !strings.Contains(out, `"^app\\.test$"`) || !strings.Contains(out, `"^other\\.test$"`) || !strings.Contains(errOut, "the run's scope:") || !strings.Contains(errOut, "listing the hosts it mapped instead") {
		t.Errorf("a run whose scope file is gone: %s (stderr %q)", out, errOut)
	}
}
