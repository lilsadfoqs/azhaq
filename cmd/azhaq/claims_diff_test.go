package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// diffDB makes a workspace of one run holding the given entities, each with
// the observations given as collector kind payload.
func diffDB(t *testing.T, name string, ents map[string][][3]string) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), name)
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for key, obs := range ents {
		typ := types.TypeHostname
		if strings.Contains(key, "://") {
			typ = types.TypeURL
		}
		e, err := st.UpsertEntity(typ, key, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if _, err := st.AddObservation(e.ID, types.Observation{Collector: o[0], Kind: o[1], Payload: json.RawMessage(o[2]), ObservedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db
}

func diffRows(t *testing.T, out string) (kinds map[string][]string, sum map[string]any) {
	t.Helper()
	kinds = map[string][]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		k := m["kind"].(string)
		if k == "summary" {
			sum = m
			continue
		}
		kinds[k] = append(kinds[k], fmt.Sprint(m["key"]))
	}
	return kinds, sum
}

// -quiet prints entities and counts only: no observation lines, and the count
// of the new observations is still in the summary.
func TestDiffQuietPrintsEntitiesAndCountsOnly(t *testing.T) {
	oldDB := diffDB(t, "a.db", map[string][][3]string{"a.test": {{"azhaq-dns", "dns", `{"fqdn":"a.test","ips":["192.0.2.1"]}`}}})
	newDB := diffDB(t, "b.db", map[string][][3]string{
		"a.test": {{"azhaq-dns", "dns", `{"fqdn":"a.test","ips":["192.0.2.1"]}`}},
		"b.test": {{"azhaq-dns", "dns", `{"fqdn":"b.test","ips":["192.0.2.2"]}`}},
	})
	out, _, err := captureBoth(t, func() error { return printDiff(oldDB, newDB, diffOpts{JSONL: true}) })
	if err != nil {
		t.Fatal(err)
	}
	kinds, sum := diffRows(t, out)
	if len(kinds["observation"]) == 0 || sum["observations"] != float64(len(kinds["observation"])) {
		t.Fatalf("without -quiet: %v %v", kinds, sum)
	}
	out, _, err = captureBoth(t, func() error { return printDiff(oldDB, newDB, diffOpts{JSONL: true, Quiet: true}) })
	if err != nil {
		t.Fatal(err)
	}
	kinds, sum = diffRows(t, out)
	if len(kinds["observation"]) != 0 || len(kinds["added"]) != 1 || kinds["added"][0] != "b.test" || sum["observations"] == float64(0) {
		t.Errorf("-quiet: rows %v, summary %v: want the added entity, no observation line, and the observations counted", kinds, sum)
	}
	text, _, err := captureBoth(t, func() error { return printDiff(oldDB, newDB, diffOpts{Quiet: true}) })
	if err != nil || strings.Contains(text, "azhaq-dns") || !strings.Contains(text, "+ Hostname b.test") && !strings.Contains(text, "b.test") || !strings.Contains(text, "observations=") {
		t.Errorf("-quiet text report: %q (%v)", text, err)
	}
}

// A workspace with only one run says so: a diff needs two.
func TestDiffOfAWorkspaceWithOneRunSaysSo(t *testing.T) {
	db := diffDB(t, "w.db", map[string][][3]string{"a.test": {{"azhaq-dns", "dns", `{"fqdn":"a.test"}`}}})
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BeginRun("r1", 1, 10); err != nil {
		t.Fatal(err)
	}
	st.Close()
	text, _, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db}) })
	if err != nil || !strings.Contains(text, "holds 1 run so far: a diff needs two") {
		t.Errorf("text: %q (%v)", text, err)
	}
	js, _, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db, "-json"}) })
	_, sum := diffRows(t, js)
	if err != nil || sum["note"] != "one run so far: a diff needs two" || sum["added"] != 0.0 {
		t.Errorf("json: %q (%v)", js, err)
	}
}

// removed is what answered in the older run; not_seen_again is what the older
// run only heard of and never checked, which its absence says little about.
func TestDiffNotSeenAgainIsWhatTheOlderRunOnlyHeardOf(t *testing.T) {
	oldDB := diffDB(t, "a.db", map[string][][3]string{
		"answered.test":     {{"azhaq-dns", "dns", `{"fqdn":"answered.test","ips":["192.0.2.1"]}`}},
		"heard.test":        {{"azhaq-subs", "name", `{"fqdn":"heard.test","sources":["crtsh"]}`}},
		"http://page.test/": {{"azhaq-http", "application", `{"url":"http://page.test/","status":200}`}},
		"http://link.test/": {{"azhaq-crawl", "link", `{"url":"http://link.test/"}`}},
		"kept.test":         {{"azhaq-dns", "dns", `{"fqdn":"kept.test","ips":["192.0.2.3"]}`}},
	})
	newDB := diffDB(t, "b.db", map[string][][3]string{"kept.test": {{"azhaq-dns", "dns", `{"fqdn":"kept.test","ips":["192.0.2.3"]}`}}})
	out, _, err := captureBoth(t, func() error { return printDiff(oldDB, newDB, diffOpts{JSONL: true, Quiet: true}) })
	if err != nil {
		t.Fatal(err)
	}
	kinds, sum := diffRows(t, out)
	slices := func(s []string) string { sort.Strings(s); return strings.Join(s, " ") }
	if slices(kinds["removed"]) != "answered.test http://page.test/" || slices(kinds["not_seen_again"]) != "heard.test http://link.test/" ||
		sum["removed"] != 2.0 || sum["not_seen_again"] != 2.0 {
		t.Errorf("removed %v, not_seen_again %v, summary %v", kinds["removed"], kinds["not_seen_again"], sum)
	}
}

// -quiet keeps the changed rows: it drops the observation lines and nothing
// else, and the summary still counts them.
func TestDiffQuietKeepsTheChangedRowsAndDropsTheObservations(t *testing.T) {
	page := func(title string) [][3]string {
		return [][3]string{{"azhaq-http", "http", `{"url":"http://a.test/page","status":200,"title":"` + title + `"}`}}
	}
	oldDB := diffDB(t, "a.db", map[string][][3]string{"http://a.test/page": page("Old")})
	newDB := diffDB(t, "b.db", map[string][][3]string{
		"http://a.test/page": page("New"),
		"b.test":             {{"azhaq-dns", "dns", `{"fqdn":"b.test","ips":["192.0.2.2"]}`}},
	})
	for _, quiet := range []bool{false, true} {
		out, _, err := captureBoth(t, func() error { return printDiff(oldDB, newDB, diffOpts{JSONL: true, Quiet: quiet}) })
		if err != nil {
			t.Fatal(err)
		}
		kinds, sum := diffRows(t, out)
		if len(kinds["changed"]) != 1 || len(kinds["added"]) != 1 || sum["changed"] != 1.0 {
			t.Errorf("quiet=%v: rows %v summary %v, want one added and one changed row", quiet, kinds, sum)
		}
		if got := len(kinds["observation"]); (got == 0) != quiet || sum["observations"] == 0.0 {
			t.Errorf("quiet=%v: %d observation lines, summary %v", quiet, got, sum["observations"])
		}
		text, _, err := captureBoth(t, func() error { return printDiff(oldDB, newDB, diffOpts{Quiet: quiet}) })
		if err != nil || !strings.Contains(text, "~ page http://a.test/page: [200] Old → [200] New") || !strings.Contains(text, "changed=1") {
			t.Errorf("quiet=%v: text report %q (%v)", quiet, text, err)
		}
	}
}

// A route that is new or gone is an entity added or removed, not a change:
// two runs of an app whose script drops one route and calls another give an
// added row, a removed row and no changed row.
func TestDiffANewOrGoneRouteIsAddedOrRemovedNotChanged(t *testing.T) {
	var mu sync.Mutex
	v2 := false
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><title>app</title><script src="/main.js"></script></html>`))
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			js := `fetch("/api/keep"); fetch("/api/old");`
			if v2 {
				js = `fetch("/api/keep"); fetch("/api/fresh");`
			}
			w.Write([]byte(js))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	db := filepath.Join(t.TempDir(), "ws.db")
	watch := func() {
		capture(t, func() error {
			return cmdWatch([]string{"-db", db, "-json", "--", "-url", site.URL + "/", "-skip", "azhaq-paths"})
		})
	}
	watch()
	mu.Lock()
	v2 = true
	mu.Unlock()
	watch()
	out, errOut, err := captureBoth(t, func() error { return cmdDiff([]string{"-db", db, "-json", "-quiet"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	kinds, sum := diffRows(t, out)
	has := func(rows []string, suffix string) bool {
		for _, r := range rows {
			if strings.HasSuffix(r, suffix) {
				return true
			}
		}
		return false
	}
	if !has(kinds["added"], "/api/fresh") || !has(kinds["removed"], "/api/old") || len(kinds["changed"]) != 0 || sum["changed"] != 0.0 {
		t.Errorf("rows %v, summary %v: want /api/fresh added, /api/old removed, nothing changed", kinds, sum)
	}
}
