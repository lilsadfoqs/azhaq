package pathscol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/statechange"
	"github.com/lilsadfoqs/azhaq/types"
)

// The root sweep asks the paths the detection templates ask: an answer that
// matches names the product in a "detected" row, and a path asked only for
// that is not a row of the map (#498).
func TestSweepNamesProductsAtTemplatePaths(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("<html><title>Files</title></html>"))
		case "/status.php":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"installed":true,"version":"10.12.1.3","versionstring":"10.12.1","edition":"Community","productname":"ownCloud"}`))
		case "/login":
			_, _ = w.Write([]byte(`<html><head><title>Grafana</title></head><script>{"subTitle":"Grafana v8.2.6 (abc)"}</script></html>`))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if words := ProductWords(); !slices.Contains(words, "status.php") || slices.Contains(words, "login") {
		t.Fatal("status.php is a product check, login a built-in path check")
	}
	col := &Collector{Client: srv.Client(), Wordlist: []string{"login"}, ProductChecks: true}
	named := map[string]string{}
	var mapped []string
	var record map[string]any
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var p struct {
			URL      string              `json:"url"`
			Path     string              `json:"path"`
			Detected []map[string]string `json:"detected"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case DetectedKind:
			for _, d := range p.Detected {
				named[p.Path] = d["product"] + " " + d["version"]
			}
			if p.URL != srv.URL+"/" {
				t.Errorf("a detection is the root's: %s", p.URL)
			}
		case "url":
			mapped = append(mapped, p.Path)
		case SweepKind:
			_ = json.Unmarshal(o.Payload, &record)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if named["/login"] != "Grafana 8.2.6" || named["/status.php"] == "" {
		t.Errorf("named %v", named)
	}
	if !slices.Equal(mapped, []string{"/login"}) {
		t.Errorf("rows of the map %v: status.php was asked only to name a product", mapped)
	}
	// The record counts the path checks as before, and the product checks apart.
	pc, _ := record["product_checks"].(map[string]any)
	if record["planned"] != float64(1) || record["sent"] != float64(1) || pc["listed"] != float64(len(ProductWords())) || pc["sent"] != pc["listed"] {
		t.Errorf("sweep record %v", record)
	}
	// Without product checks (-known-files) the sweep asks only its list.
	fetch.Reset()
	col = &Collector{Client: srv.Client(), Wordlist: []string{"login"}}
	n := 0
	_, _ = col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		if o.Kind == DetectedKind && strings.Contains(string(o.Payload), "status.php") {
			n++
		}
		return nil
	})
	if n != 0 {
		t.Error("a sweep without product checks asked status.php")
	}
}

// A product check never declares a state change and is never the root with
// a query: those a run does not send unasked, and the root is the page.
func TestProductWordsLeaveOutStateChangesAndTheRoot(t *testing.T) {
	words := ProductWords()
	if len(words) < 500 {
		t.Fatalf("%d product checks", len(words))
	}
	for _, w := range words {
		if word, _ := statechange.OfTarget("/" + w); word != "" {
			t.Errorf("%s declares a state change (%s)", w, word)
		}
		if path, _, _ := strings.Cut(w, "?"); path == "" || strings.Contains(w, "#") || slices.Contains(DefaultWordlist, w) {
			t.Errorf("%s is the root, a fragment or a built-in check", w)
		}
	}
}

// A site that answers every path with its application page is asked every
// product check all the same, holds one copy of that page in the process, and
// a path whose page names a product still names it (#505).
func TestCatchAllSiteIsAskedEveryProductCheck(t *testing.T) {
	fetch.Reset()
	t.Cleanup(fetch.Reset)
	page := []byte("<html><head><title>Shop</title></head><body>" + strings.Repeat("<p>the application</p>", 3000) + "</body></html>")
	var asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.URL.Path == "/login" {
			_, _ = w.Write([]byte(`<html><head><title>Grafana</title></head><script>{"subTitle":"Grafana v8.2.6 (abc)"}</script></html>`))
			return
		}
		_, _ = w.Write(page)
	}))
	t.Cleanup(srv.Close)
	col := &Collector{Client: srv.Client(), Wordlist: []string{"login"}, ProductChecks: true}
	named := map[string]string{}
	var record map[string]any
	_, err := col.Run(context.Background(), types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/"}}, func(o types.Observation) error {
		var p struct {
			Path     string              `json:"path"`
			Detected []map[string]string `json:"detected"`
		}
		_ = json.Unmarshal(o.Payload, &p)
		switch o.Kind {
		case DetectedKind:
			for _, d := range p.Detected {
				named[p.Path] = d["product"] + " " + d["version"]
			}
		case SweepKind:
			_ = json.Unmarshal(o.Payload, &record)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	words := len(ProductWords())
	// The product checks, the path check and its control requests.
	if got := int(asked.Load()); got < words+1 || got > words+4 {
		t.Errorf("asked %d, want %d product checks and the path check", got, words)
	}
	if pc, _ := record["product_checks"].(map[string]any); pc["listed"] != float64(words) || pc["sent"] != pc["listed"] {
		t.Errorf("sweep record %v", record)
	}
	if named["/login"] != "Grafana 8.2.6" {
		t.Errorf("named %v", named)
	}
	var first []byte
	copies := 0
	for _, w := range ProductWords() {
		res, ok := fetch.Cached(srv.URL + "/" + w)
		if !ok || len(res.Body) != len(page) {
			continue
		}
		if first == nil {
			first = res.Body
		}
		if &res.Body[0] == &first[0] {
			copies++
		}
	}
	if copies < words*95/100 { // a few paths are cached under a spelling of their own
		t.Errorf("%d of %d answers share one copy of the page", copies, words)
	}
}
