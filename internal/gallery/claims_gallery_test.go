package gallery

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// The page's Content-Security-Policy lets the browser load only the page's
// own script and style, from this server, and connect nowhere else.
func TestCSPLetsTheBrowserLoadOnlyItsOwnScriptAndStyle(t *testing.T) {
	_, db := makeWorkspace(t, t.TempDir(), "c.db", 5)
	s := newSrv(t, db)
	for _, p := range []string{"/", "/app.js", "/app.css", "/api/stats", "/api/shots"} {
		r, err := http.Get(s.ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		policy := r.Header.Get("Content-Security-Policy")
		dirs := map[string]string{}
		for _, d := range strings.Split(policy, ";") {
			name, val, _ := strings.Cut(strings.TrimSpace(d), " ")
			dirs[name] = val
		}
		if dirs["default-src"] != "'none'" || dirs["script-src"] != "'self'" || dirs["style-src"] != "'self'" || dirs["connect-src"] != "'self'" || dirs["img-src"] != "'self'" {
			t.Errorf("%s: policy %q", p, policy)
		}
		if strings.Contains(policy, "http") || strings.Contains(policy, "*") || strings.Contains(policy, "unsafe") {
			t.Errorf("%s: the policy names another source: %q", p, policy)
		}
	}
}

// The workspace is opened read-only; the pages are read once at start, so a
// page taken since is not listed, and what the workspace holds of a page's
// URL is read when it is asked for.
func TestWorkspaceIsOpenedReadOnlyAndItsPagesAreReadOnceAtStart(t *testing.T) {
	dir := t.TempDir()
	rows, db := makeWorkspace(t, dir, "r.db", 6)
	sum := func() [32]byte {
		raw, err := os.ReadFile(db)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(raw)
	}
	before := sum()
	s := newSrv(t, db)
	var l List
	s.get("/api/shots?limit=50", &l)
	for _, p := range []string{"/api/stats", "/api/facets", "/api/groups", "/api/failed"} {
		s.get(p, nil)
	}
	for _, sh := range l.Shots {
		s.get("/api/shots/"+sh.ID, nil)
		s.get("/api/shots/"+sh.ID+"/show", nil)
		s.get("/img/"+sh.ID+"/thumb", nil)
	}
	if sum() != before {
		t.Error("serving the workspace changed its file")
	}
	if _, err := s.g.srcs[0].db.Exec(`INSERT INTO entities (id, type, key, first_seen, last_seen) VALUES ('x', 'url', 'http://x/', 0, 0)`); err == nil {
		t.Error("the workspace was opened for writing")
	}
	// A page taken after the start, and an observation of a listed page.
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ent, err := st.UpsertEntity(types.TypeURL, "https://new.example.test/", now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"url": "https://new.example.test/", "file": "n.png", "file_path": filepath.Join(dir, "n.png"), "title": "taken since", "response_code": 200})
	if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-shots", Source: "https://new.example.test/", Kind: "screenshot", Payload: raw, ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	var first Shot
	for _, sh := range l.Shots {
		if sh.URL == rows[0].URL {
			first = *sh.Shot
		}
	}
	listed, err := st.UpsertEntity(types.TypeURL, rows[0].URL, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddObservation(listed.ID, types.Observation{Collector: "azhaq-http", Source: rows[0].URL, Kind: "application", Payload: json.RawMessage(`{"status":200}`), ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	var after List
	s.get("/api/shots?limit=50", &after)
	if after.Total != l.Total || strings.Contains(strings.Join(func() []string {
		var us []string
		for _, sh := range after.Shots {
			us = append(us, sh.URL)
		}
		return us
	}(), " "), "new.example.test") {
		t.Errorf("a page taken since the start is listed: %d pages, were %d", after.Total, l.Total)
	}
	var show struct {
		Obs []struct{ Kind string } `json:"observations"`
	}
	s.get("/api/shots/"+first.ID+"/show", &show)
	if len(show.Obs) != 2 {
		t.Errorf("what the workspace holds of the URL is read when asked: %+v", show.Obs)
	}
}

// Every response of the API is JSON, errors included; the pictures are not.
func TestEveryResponseOfTheAPIIsJSONExceptThePictures(t *testing.T) {
	_, db := makeWorkspace(t, t.TempDir(), "j.db", 8)
	s := newSrv(t, db)
	var l List
	s.get("/api/shots?limit=1", &l)
	id := l.Shots[0].ID
	for path, want := range map[string]int{
		"/api/": 200, "/api/shots": 200, "/api/shots/" + id: 200, "/api/shots/" + id + "/show": 200, "/api/facets": 200, "/api/groups": 200, "/api/failed": 200, "/api/stats": 200,
		"/api/shots?limit=abc": 400, "/api/failed?kind=x": 400, "/api/shots/nope": 404, "/api/shots/nope/show": 404, "/api/shots?sort=nope": 400,
	} {
		r, err := http.Get(s.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, r.StatusCode, want)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || !json.Valid(body) {
			t.Errorf("%s: %s %q", path, ct, body)
		}
		if r.StatusCode >= 400 && !regexp.MustCompile(`^\{"error":"`).Match(body) {
			t.Errorf("%s: an error that is not {\"error\": …}: %q", path, body)
		}
	}
	for _, kind := range []string{"thumb", "full"} {
		r, err := http.Get(s.ts.URL + "/img/" + id + "/" + kind)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
			t.Errorf("%s: %s", kind, ct)
		}
	}
}

// What the gallery cannot show it says: pages whose picture file is gone
// (partial), that carry no hash or status, and the count of pages whose text
// was kept, on /api/stats and in the page's banner.
func TestWhatTheGalleryCannotShowIsSaidAndCounted(t *testing.T) {
	dir := t.TempDir()
	rows, db := makeWorkspace(t, dir, "g.db", 14) // every 7th page keeps its HTML: 2 of 14
	if err := os.Remove(filepath.Join(dir, "g.db_1.png")); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Hour)
	old := func(u string) {
		ent, err := st.UpsertEntity(types.TypeURL, u, now)
		if err != nil {
			t.Fatal(err)
		}
		png := filepath.Join(dir, "g.db_2.png")
		raw, _ := json.Marshal(map[string]any{"url": u, "file": "g.db_2.png", "file_path": png, "title": "older azhaq"}) // no status, no hash
		if _, err := st.AddObservation(ent.ID, types.Observation{Collector: "azhaq-shots", Source: u, Kind: "screenshot", Payload: raw, ObservedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	old("https://old1.example.test/")
	old("https://old2.example.test/")
	st.Close()
	_ = rows
	s := newSrv(t, db)
	s.g.WaitBody()
	var stats Stats
	s.get("/api/stats", &stats)
	says := map[string]bool{}
	for _, w := range stats.Warnings {
		switch {
		case strings.Contains(w.Message, "the picture file is not on disk"):
			says["file"] = w.Partial && strings.HasPrefix(w.Message, "1 of 16 pages")
		case strings.Contains(w.Message, "no perceptual hash"):
			says["hash"] = !w.Partial && strings.HasPrefix(w.Message, "2 of 16 pages")
		case strings.Contains(w.Message, "no status recorded"):
			says["status"] = !w.Partial && strings.HasPrefix(w.Message, "2 of 16 pages")
		}
	}
	if !says["file"] || !says["hash"] || !says["status"] || stats.NoFile != 1 || stats.Pages != 16 || stats.Body.Kept != 2 {
		t.Errorf("warnings %+v, files missing %d, text kept for %d of %d", stats.Warnings, stats.NoFile, stats.Body.Kept, stats.Pages)
	}
	// The banner says how many pages have their text.
	js, err := uiFiles.ReadFile("ui/app.js")
	if err != nil || !strings.Contains(string(js), "Page text is kept for ${b.kept} of ${st.pages} pages") || !strings.Contains(string(js), "st.warnings.map") {
		t.Errorf("the banner: %v", err)
	}
}
