package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// coverageDB holds one URL of each coverage and the names they sit on:
// answered, not requested (a hint), kept out by a rule, asked with no
// answer, gone, and held back by a limit; and a name nothing was asked on.
func coverageDB(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "cov.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	add := func(typ types.SeedType, key string, o *types.Observation) {
		t.Helper()
		e, err := st.UpsertEntity(typ, key, now)
		if err != nil {
			t.Fatal(err)
		}
		if o == nil {
			return
		}
		o.ObservedAt = now
		if _, err := st.AddObservation(e.ID, *o); err != nil {
			t.Fatal(err)
		}
	}
	http := func(kind, payload string) *types.Observation {
		return &types.Observation{Collector: "azhaq-http", Kind: kind, Payload: json.RawMessage(payload)}
	}
	add(types.TypeURL, "http://app.test/", http("http", `{"status":200}`))
	add(types.TypeURL, "http://app.test/named-by-a-script", nil)
	add(types.TypeURL, "http://app.test/admin", http("skipped", `{"skipped":"-deny-path ^/admin"}`))
	add(types.TypeURL, "http://app.test/slow", http("error", `{"error":"timeout"}`))
	add(types.TypeURL, "http://app.test/old", http("http", `{"status":404}`))
	add(types.TypeURL, "http://app.test/deep", nil)
	add(types.TypeURL, "http://other.test/x", nil)
	add(types.TypeURL, "http://err.test/", http("error", `{"error":"refused"}`))
	add(types.TypeHostname, "app.test", nil)
	add(types.TypeHostname, "other.test", nil)
	add(types.TypeHostname, "err.test", nil)
	add(types.TypeHostname, "lonely.test", nil)
	if err := st.SaveLeftover([]types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://app.test/deep"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCapped(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	return db
}

func exportLines(t *testing.T, db string, args ...string) []string {
	t.Helper()
	// Read while it runs: a long list does not fit the pipe captureStdout reads after.
	out, _, err := runToFile(t, append([]string{"export", "-db", db}, args...)...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	lines := strings.Fields(out)
	slices.Sort(lines)
	return lines
}

// -coverage narrows the url list as it narrows query's rows, and the plain
// list stays as it was.
func TestExportURLsCoverage(t *testing.T) {
	db := coverageDB(t)
	all := exportLines(t, db, "-format", "urls")
	if len(all) != 8 {
		t.Fatalf("the plain list holds %d URLs: %v", len(all), all)
	}
	for cov, want := range map[string]string{
		"visited": "http://app.test/",
		"hint":    "http://app.test/named-by-a-script http://other.test/x",
		"skipped": "http://app.test/admin",
		"error":   "http://app.test/slow http://err.test/",
		"gone":    "http://app.test/old",
		"capped":  "http://app.test/deep",
	} {
		got := strings.Join(exportLines(t, db, "-format", "urls", "-coverage", cov), " ")
		if got != want {
			t.Errorf("-coverage %s: %q, want %q", cov, got, want)
		}
	}
	if got := exportLines(t, db, "-format", "urls", "-coverage", "visited,gone"); len(got) != 2 {
		t.Errorf("a list of coverages: %v", got)
	}
	// What query says the same coverage holds.
	q, err := captureStdout(t, func() error {
		return run([]string{"query", "-db", db, "-type", "URL", "-coverage", "hint", "-fields", "key", "-json"})
	})
	if err != nil || strings.Count(q, "\n") != 2 {
		t.Errorf("query -coverage hint: %v\n%s", err, q)
	}
}

// -json says per URL what the list does not: how it is known and how it
// answered.
func TestExportURLsJSON(t *testing.T) {
	db := coverageDB(t)
	got := map[string]map[string]any{}
	for _, l := range exportLines(t, db, "-format", "urls", "-json") {
		var row map[string]any
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		got[row["url"].(string)] = row
	}
	if len(got) != 8 {
		t.Fatalf("%d rows", len(got))
	}
	if r := got["http://app.test/"]; r["coverage"] != "visited" || r["status"] != float64(200) || r["source"] == nil {
		t.Errorf("visited row: %v", r)
	}
	if r := got["http://app.test/named-by-a-script"]; r["coverage"] != "hint" || r["status"] != float64(0) {
		t.Errorf("hint row: %v", r)
	}
	if r := got["http://app.test/old"]; r["coverage"] != "gone" || r["status"] != float64(404) {
		t.Errorf("gone row: %v", r)
	}
	for u, r := range got {
		for _, k := range []string{"url", "coverage", "status", "source"} {
			if _, ok := r[k]; !ok {
				t.Errorf("%s lacks %q: %v", u, k, r)
			}
		}
	}
	if only := exportLines(t, db, "-format", "urls", "-json", "-coverage", "skipped"); len(only) != 1 || !strings.Contains(only[0], `"coverage":"skipped"`) {
		t.Errorf("json with a coverage: %v", only)
	}
}

// A name's coverage is that of the URLs asked on it: a name nothing was
// asked on is only named.
func TestExportNamesCoverage(t *testing.T) {
	db := coverageDB(t)
	if all := exportLines(t, db, "-format", "names"); strings.Join(all, " ") != "app.test err.test lonely.test other.test" {
		t.Errorf("the plain list: %v", all)
	}
	for cov, want := range map[string]string{
		"visited": "app.test",
		"error":   "err.test",
		"hint":    "lonely.test other.test",
	} {
		if got := strings.Join(exportLines(t, db, "-format", "names", "-coverage", cov), " "); got != want {
			t.Errorf("-coverage %s: %q, want %q", cov, got, want)
		}
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(exportLines(t, db, "-format", "names", "-json", "-coverage", "visited")[0]), &row); err != nil {
		t.Fatal(err)
	}
	if row["name"] != "app.test" || row["coverage"] != "visited" || row["status"] != float64(200) {
		t.Errorf("name row: %v", row)
	}
}

// The options mean nothing to another format, and a coverage no row has is
// a typo, not an empty list.
func TestExportCoverageIsForLists(t *testing.T) {
	db := coverageDB(t)
	for _, args := range [][]string{
		{"-format", "hosts", "-coverage", "visited"},
		{"-format", "jsonl", "-json"},
		{"-format", "openapi", "-coverage", "hint"},
		{"-format", "urls", "-coverage", "seen"},
	} {
		if err := run(append([]string{"export", "-db", db}, args...)); exitCode(err) != exitUsage || !strings.Contains(err.Error(), "urls") && !strings.Contains(err.Error(), "visited") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// An archived URL no request was made for is a hint, whose source is the
// archive, whether the graph holds it or only the list beside the workspace.
func TestExportURLsCoverageOfArchived(t *testing.T) {
	flag, _ := archiveStandIn(t, 900)
	db := filepath.Join(t.TempDir(), "t.db")
	if _, _, err := runToFile(t, "urls", "-d", "lab7stand.org", "-providers", "wayback", "-archive", flag, "-urls-pause", "0", "-silent", "-db", db); err != nil {
		t.Fatal(err)
	}
	hints := exportLines(t, db, "-format", "urls", "-json", "-coverage", "hint")
	if len(hints) != 900 {
		t.Fatalf("%d hints, want 900", len(hints))
	}
	if n := len(exportLines(t, db, "-format", "urls", "-coverage", "visited")); n != 0 {
		t.Errorf("%d visited URLs from an archive", n)
	}
	// The graph's rows say azhaq-urls, the list's the archive that gave the URL.
	fromList := 0
	for _, l := range hints {
		switch {
		case strings.Contains(l, `"source":"wayback"`):
			fromList++
		case !strings.Contains(l, `"source":"azhaq-urls"`):
			t.Fatalf("no archive as source: %s", l)
		}
	}
	if fromList != 700 {
		t.Errorf("%d URLs of the list beside the workspace, want the 700 the graph does not hold", fromList)
	}
}

// A coverage no entry has gives an empty list, said on stderr, and exit 0.
func TestExportCoverageMatchesNothing(t *testing.T) {
	db := coverageDB(t)
	out, errOut, err := runToFile(t, "export", "-db", db, "-format", "urls", "-coverage", "catchall")
	if err != nil || out != "" || !strings.Contains(errOut, "nothing to write: no entry has coverage catchall") {
		t.Errorf("%v, stdout %q, stderr %q", err, out, errOut)
	}
}
