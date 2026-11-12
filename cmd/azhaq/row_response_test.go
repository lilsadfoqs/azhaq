package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A site whose answers carry a nonce and a date: two runs of it differ in
// exactly the fields a row keeps of its answer.
func evidenceSite(t *testing.T, big string) *httptest.Server {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Nonce", fmt.Sprint(n.Add(1)))
		w.Header().Set("X-Stub", "evidence")
		w.Header().Set("Set-Cookie", "srv=session-VALUE; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>home</title><a href="/big">big</a><a href="/small">small</a></html>`)
		case "/big":
			fmt.Fprint(w, big)
		case "/small":
			fmt.Fprint(w, `<html><title>small</title>tiny</html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func evidenceBig() string {
	return "<html><title>big</title><body>" + strings.Repeat("0123456789abcdef", 300) + "</body></html>"
}

func evidenceRun(t *testing.T, site *httptest.Server, extra ...string) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "w.db")
	args := append([]string{"run", "-url", site.URL + "/", "-allow", "127.0.0.1", "-db", db, "-quiet", "-no-paths", "-json"}, extra...)
	cli(t, args...)
	return db
}

type answerRow struct {
	Key        string              `json:"key"`
	Headers    map[string][]string `json:"headers"`
	Excerpt    string              `json:"body_excerpt"`
	BodyLength int                 `json:"body_length"`
	BodyCut    bool                `json:"body_cut"`
	AskedAt    string              `json:"asked_at"`
}

func queryAnswer(t *testing.T, db, match string) answerRow {
	t.Helper()
	out, _, _ := cli(t, "query", "-db", db, "-json", "-match", match, "-fields", "key,headers,body_excerpt,body_length,body_cut,asked_at")
	var r answerRow
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])), &r); err != nil || r.Key == "" {
		t.Fatalf("%s: %v: %q", match, err, out)
	}
	return r
}

func TestRowKeepsResponseHeadersAndBodyStart(t *testing.T) {
	big := evidenceBig()
	site := evidenceSite(t, big)
	db := evidenceRun(t, site, "-cookie", "sid=cookie-SECRET", "-header", "Authorization: Bearer token-SECRET")

	r := queryAnswer(t, db, "/big")
	if r.Headers["X-Stub"][0] != "evidence" || r.Headers["Content-Type"][0] != "text/html" || r.Headers["X-Nonce"] == nil {
		t.Errorf("response headers: %v", r.Headers)
	}
	// Only the response's: what the run sent is never stored.
	for _, k := range []string{"Cookie", "Authorization", "User-Agent", "Accept-Encoding"} {
		if _, ok := r.Headers[k]; ok {
			t.Errorf("request header %s stored", k)
		}
	}
	if got := r.Headers["Set-Cookie"]; len(got) != 1 || strings.Contains(got[0], "session-VALUE") || !strings.HasPrefix(got[0], "srv=") || !strings.Contains(got[0], "HttpOnly") {
		t.Errorf("a cookie keeps its name and flags, not its value: %v", got)
	}
	if len(r.Excerpt) != 1024 || r.Excerpt != big[:1024] || !r.BodyCut || r.BodyLength != len(big) {
		t.Errorf("excerpt %d bytes, cut %v, length %d of %d", len(r.Excerpt), r.BodyCut, r.BodyLength, len(big))
	}
	if r.AskedAt == "" {
		t.Error("no time the answer was asked")
	}

	s := queryAnswer(t, db, "/small")
	if !strings.Contains(s.Excerpt, "tiny") || s.BodyCut || s.BodyLength != len(s.Excerpt) {
		t.Errorf("a short body is kept whole and not cut: %+v", s)
	}

	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"cookie-SECRET", "token-SECRET"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%s is in the database", secret)
		}
	}
	// What a row keeps: the resume buffer of the run's answers leaves bytes in the
	// file's free pages, so the cookie's value is looked for in what is read back.
	exp, _, _ := cli(t, "export", "-db", db, "-format", "jsonl")
	if strings.Contains(exp, "session-VALUE") {
		t.Error("a cookie's value is in what the workspace holds")
	}
}

func TestResponseFieldsAreNotInTheDefaultRows(t *testing.T) {
	site := evidenceSite(t, evidenceBig())
	db := filepath.Join(t.TempDir(), "w.db")
	out, _, _ := cli(t, "run", "-url", site.URL+"/", "-allow", "127.0.0.1", "-db", db, "-no-paths", "-json")
	q, _, _ := cli(t, "query", "-db", db, "-json")
	for name, text := range map[string]string{"run -json": out, "query -json": q} {
		for _, f := range responseFields {
			if strings.Contains(text, `"`+f+`"`) {
				t.Errorf("%s prints %s by default", name, f)
			}
		}
	}
}

func TestShowAndExportPrintTheKeptAnswer(t *testing.T) {
	big := evidenceBig()
	site := evidenceSite(t, big)
	db := evidenceRun(t, site)

	out, _, _ := cli(t, "show", "-db", db, site.URL+"/big")
	for _, want := range []string{"answer asked ", "X-Stub: evidence", "body: first 1024 of " + fmt.Sprint(len(big)) + " bytes", big[:40]} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	js, _, _ := cli(t, "show", "-db", db, "-json", site.URL+"/big")
	var shown struct {
		Response answerRow `json:"response"`
	}
	if err := json.Unmarshal([]byte(js), &shown); err != nil || shown.Response.Excerpt != big[:1024] || !shown.Response.BodyCut {
		t.Errorf("show -json: %v %+v", err, shown.Response)
	}

	exp, _, _ := cli(t, "export", "-db", db, "-format", "jsonl")
	var entity, observation bool
	for _, l := range strings.Split(exp, "\n") {
		var rec struct {
			Kind   string `json:"kind"`
			Entity struct {
				Key string `json:"key"`
			} `json:"entity"`
			Observation struct {
				Payload struct {
					URL     string `json:"url"`
					Excerpt []byte `json:"body_excerpt"` // base64 in the payload
				} `json:"payload"`
			} `json:"observation"`
			answerRow
		}
		if json.Unmarshal([]byte(l), &rec) != nil {
			continue
		}
		if rec.Kind == "entity" && rec.Entity.Key == site.URL+"/big" {
			entity = rec.Headers["X-Stub"] != nil && rec.BodyCut && rec.BodyLength == len(big)
		}
		if p := rec.Observation.Payload; rec.Kind == "observation" && p.URL == site.URL+"/big" {
			observation = observation || string(p.Excerpt) == big[:1024]
		}
	}
	if !entity || !observation {
		t.Errorf("export jsonl: the entity record has the answer's headers %v, the observation its body's start %v", entity, observation)
	}

	page, _, _ := cli(t, "export", "-db", db, "-format", "html")
	if !strings.Contains(page, "X-Stub: evidence") || strings.Contains(page, big[:40]) {
		t.Error("the HTML report shows the answer's headers and not its body")
	}
}

func TestDiffIgnoresTheKeptAnswer(t *testing.T) {
	site := evidenceSite(t, evidenceBig())
	a, b := evidenceRun(t, site), evidenceRun(t, site)
	// The runs do differ in what a row keeps: a nonce in every answer.
	if x, y := queryAnswer(t, a, "/big"), queryAnswer(t, b, "/big"); x.Headers["X-Nonce"][0] == y.Headers["X-Nonce"][0] {
		t.Fatalf("the nonce did not change: %v", x.Headers["X-Nonce"])
	}
	out, _, _ := cli(t, "diff", "-a", a, "-b", b, "-json")
	kinds, sum := diffRows(t, out)
	if len(kinds) != 0 || sum["observations"] != float64(0) {
		t.Errorf("diff of two identical runs: %v %v", kinds, sum)
	}
}

func TestStoredResponsesStillKeepWholeBodies(t *testing.T) {
	big := evidenceBig()
	site := evidenceSite(t, big)
	dir := t.TempDir()
	evidenceRun(t, site, "-sr", "-srd", dir)
	var most int64
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			most = max(most, fi.Size())
		}
		return nil
	})
	if most < int64(len(big)) {
		t.Errorf("-sr's biggest file is %d bytes; the body is %d", most, len(big))
	}
}
