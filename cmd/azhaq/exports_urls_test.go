package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// The workspace keeps one example of each archived URL shape, not every
// URL a urls run printed; export and query say so, and where the whole
// list is.
func TestExportURLsSaysWhatTheWorkspaceKeeps(t *testing.T) {
	db := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	dom, err := st.UpsertEntity(types.TypeDomain, "lab7stand.org", now)
	if err != nil {
		t.Fatal(err)
	}
	add := func(e types.Entity, kind string, payload string) {
		t.Helper()
		if _, err := st.AddObservation(e.ID, types.Observation{Collector: "azhaq-urls", Source: "archives", Kind: kind, Payload: json.RawMessage(payload), ObservedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	add(dom, "urls", `{"domain":"lab7stand.org","count":12000,"templates":2}`)
	for _, u := range []string{"http://lab7stand.org/a/b.php", "http://lab7stand.org/c/d.php"} {
		e, err := st.UpsertEntity(types.TypeURL, u, now)
		if err != nil {
			t.Fatal(err)
		}
		add(e, "url", `{"url":"`+u+`","via":"archive","count":6000}`)
	}
	st.Close()

	out, errOut, err := captureBoth(t, func() error { return run([]string{"export", "-db", db, "-format", "urls"}) })
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(out)) != 2 {
		t.Fatalf("export wrote %q", out)
	}
	for _, want := range []string{"2 template examples of the 12000 archived URLs", "urls -o"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("export stderr lacks %q: %q", want, errOut)
		}
	}
	_, errOut, err = captureBoth(t, func() error { return run([]string{"query", "-db", db, "-type", "URL", "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "2 template examples of the 12000 archived URLs") {
		t.Errorf("query summary lacks the note: %q", errOut)
	}
}
