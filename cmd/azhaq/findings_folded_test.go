package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// foldedHintsDB holds the hints of a page: two images no request asked for,
// two routes only a script names, and four pages it links (three of them one
// template), which the map lists. Nothing is verified.
func foldedHintsDB(t *testing.T, listed ...string) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "x.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	page, _ := st.UpsertEntity(types.TypeURL, "http://app.test/", now)
	if _, err := st.AddObservation(page.ID, types.Observation{Collector: "azhaq-http", Kind: "http", Payload: json.RawMessage(`{"status":200}`), ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	add := func(key, collector string) {
		e, _ := st.UpsertEntity(types.TypeURL, key, now)
		_ = st.AddEdge(page.ID, e.ID, "FOUND", now)
		payload := json.RawMessage(fmt.Sprintf(`{"url":%q,"via":"js-string"}`, key))
		if _, err := st.AddObservation(page.ID, types.Observation{Collector: collector, Kind: "url", Payload: payload, ObservedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	add("http://app.test/img/a.png", "azhaq-crawl")
	add("http://app.test/img/b.png", "azhaq-crawl")
	add("http://app.test/only-in-script", "azhaq-js")
	add("http://app.test/also-in-script", "azhaq-js")
	for _, k := range listed {
		add(k, "azhaq-crawl")
	}
	st.Close()
	return db
}

func reportLines(t *testing.T, db string, args ...string) []map[string]any {
	t.Helper()
	out, _, err := captureBoth(t, func() error {
		return cmdReport(append([]string{"-findings", "-db", db}, args...))
	})
	if err != nil {
		t.Fatal(err)
	}
	return jsonRows(t, out)
}

// The leads are the hints the map lists: a hint its default view folds is
// counted by class, one line each, and leads + the folded counts are the
// rows query -coverage hint lists.
func TestFindingsLeadsLeaveOutFoldedRows(t *testing.T) {
	db := foldedHintsDB(t, "http://app.test/about", "http://app.test/item?id=1", "http://app.test/item?id=2", "http://app.test/item?id=3")
	var leads, folded int
	classes := map[string]int{}
	for _, l := range reportLines(t, db, "-format", "jsonl") {
		switch l["type"] {
		case "lead":
			leads++
			if strings.Contains(l["url"].(string), "/img/") || strings.Contains(l["url"].(string), "in-script") {
				t.Errorf("a folded row is a lead: %v", l)
			}
		case "folded":
			classes[l["class"].(string)] = int(l["count"].(float64))
			folded += int(l["count"].(float64))
			if l["line"] == "" {
				t.Errorf("a fold line without its text: %v", l)
			}
		}
	}
	if leads != 4 || classes["beyond-depth"] != 2 || classes["unrequested"] != 2 || len(classes) != 2 {
		t.Errorf("%d leads, folds %v; want 4 leads, beyond-depth 2, unrequested 2", leads, classes)
	}

	// The arithmetic: leads + folds are the hint rows of query (a templated
	// row stands for its count).
	out, _, err := captureBoth(t, func() error {
		return run([]string{"query", "-db", db, "-coverage", "hint", "-type", "URL", "-json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	hints := 0
	for _, r := range jsonRows(t, out) {
		if r["type"] != "URL" {
			continue
		}
		if n, ok := r["count"].(float64); ok && n > 1 {
			hints += int(n)
		} else {
			hints++
		}
	}
	if hints != leads+folded {
		t.Errorf("query -coverage hint lists %d URLs, the report has %d leads and %d folded", hints, leads, folded)
	}

	// Markdown and the export say the same, and the stderr line counts the fold.
	var md bytes.Buffer
	if err := exportAs(db, "findings-md", "", &md); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Folded hints (4)", "folded beyond-depth: 2 assets", "folded unrequested: 2 URLs", "4 leads"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("findings-md lacks %q:\n%s", want, md.String())
		}
	}
	var ex bytes.Buffer
	if err := exportAs(db, "findings", "", &ex); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(ex.String(), `"type":"lead"`); n != 4 {
		t.Errorf("export findings has %d leads, want 4", n)
	}
	_, errOut, err := captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-o", filepath.Join(t.TempDir(), "f.jsonl")})
	})
	if err != nil || !strings.Contains(errOut, "0 findings, 0 identifications, 4 leads, 4 hints folded (beyond-depth 2, unrequested 2)") {
		t.Errorf("%v: %s", err, errOut)
	}
}

// A workspace whose hints all fold has no lead: the explicit empty line
// stays first, now with the count folded, and the fold lines follow.
func TestFindingsAllHintsFolded(t *testing.T) {
	db := foldedHintsDB(t)
	ls := reportLines(t, db, "-format", "jsonl")
	if len(ls) != 3 || ls[0]["type"] != "findings" || ls[0]["leads"] != float64(0) || ls[0]["folded"] != float64(4) || ls[1]["type"] != "folded" {
		t.Errorf("lines: %v", ls)
	}
}
