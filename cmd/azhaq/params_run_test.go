package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

func TestRunParamsKeepsWhatParamsFinds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Has("q") {
			fmt.Fprint(w, `{"status":"success","data":[`+strings.Repeat(`{"id":1,"name":"Apple Juice","price":1.99},`, 40)+`{"id":2}]}`)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":[]}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	words := filepath.Join(dir, "q.txt")
	var ws []string
	for i := 0; i < 20; i++ {
		ws = append(ws, fmt.Sprintf("word%d", i))
	}
	ws = append(ws, "q")
	os.WriteFile(words, []byte(strings.Join(ws, "\n")+"\n"), 0o644)
	db := filepath.Join(dir, "r.db")
	_, rep, code := runContract(t, "run", "-url", srv.URL+"/rest/products/search", "-params", words, "-no-paths", "-depth", "0", "-max-requests", "35", "-timeout", "15s", "-db", db)
	if code != exitOK {
		t.Fatalf("exit %d, notes %q", code, rep.Notes)
	}
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": srv.URL + "/rest/products/search"}}
	var got []string
	for _, r := range engine.BuildMap(ents, []types.Seed{seed}, obs, nil, false) {
		if strings.HasSuffix(r.Entity.Key, "/rest/products/search") {
			got = r.Params
		}
	}
	if len(got) != 1 || got[0] != "q" {
		t.Errorf("the map row's params %v, want [q]: what -params found is lost", got)
	}
}

// A name the URL already carries is printed as given and is not counted as
// found: the summary counts the names the search found and the ones given.
func TestParamsMarksTheNamesTheURLGaveAndDoesNotCountThemAsFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "<html>" + strings.Repeat("all products ", 500)
		if r.URL.Query().Has("q") {
			body = "<html>" + strings.Repeat("a ", 100)
		}
		if r.URL.Query().Has("zebra") {
			body += strings.Repeat(" zebra stripes", 80)
		}
		fmt.Fprint(w, body+"</html>")
	}))
	defer srv.Close()
	words := []string{"zebra"}
	for i := range 100 {
		words = append(words, fmt.Sprintf("noise%d", i))
	}
	list := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(list, []byte(strings.Join(words, "\n")+"\n"), 0o644)
	out, rep, code := runContract(t, "params", "-u", srv.URL+"/search?q=apple", "-w", list, "-rate", "0")
	if code != exitOK {
		t.Fatalf("exit %d, notes %q", code, rep.Notes)
	}
	rows := jsonRows(t, out)
	if len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	why, _ := rows[0]["why"].(map[string]any)
	if g, _ := rows[0]["given"].([]any); len(g) != 1 || g[0] != "q" || why["q"] != "in the URL given; size" || fmt.Sprint(why["zebra"]) == "" || strings.HasPrefix(fmt.Sprint(why["zebra"]), "in the URL given") {
		t.Errorf("row %v", rows[0])
	}
	if rep.Counts["parameters found"] != 1 || rep.Counts["given in the URL"] != 1 || rep.Results != 1 {
		t.Errorf("results %d, counts %v", rep.Results, rep.Counts)
	}
	// The URL's own name alone is a page with nothing found: its row is printed, and no find is counted.
	os.WriteFile(list, []byte(strings.Join(words[1:], "\n")+"\n"), 0o644)
	_, rep, _ = runContract(t, "params", "-u", srv.URL+"/search?q=apple", "-w", list, "-rate", "0")
	if rep.Counts["parameters found"] != 0 || rep.Counts["given in the URL"] != 1 {
		t.Errorf("only a given name: counts %v", rep.Counts)
	}
}
