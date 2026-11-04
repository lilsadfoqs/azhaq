package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// newRows runs azhaq new -json over db and gives the keys it lists.
func newRows(t *testing.T, db string, extra ...string) []string {
	t.Helper()
	out, _, err := captureBoth(t, func() error { return cmdNew(append([]string{"-db", db, "-json"}, extra...)) })
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["key"] != nil {
			keys = append(keys, m["key"].(string))
		}
	}
	sort.Strings(keys)
	return keys
}

// new leaves out what the newest run no longer saw, and URLs that answer
// with the catch-all page, scripts, assets and source maps, whether the run
// read them as such or their address says so.
func TestNewLeavesOutWhatTheNewestRunDidNotSeeCatchAllsAndAssets(t *testing.T) {
	db := filepath.Join(t.TempDir(), "w.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	see := func(key string, payload string) {
		t.Helper()
		typ := types.TypeURL
		if !strings.Contains(key, "://") {
			typ = types.TypeHostname
		}
		e, err := st.UpsertEntity(typ, key, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.AddObservation(e.ID, types.Observation{Collector: "azhaq-http", Kind: "application", Payload: json.RawMessage(payload), ObservedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	page := func(u string) string { return `{"url":"` + u + `","status":200,"title":"t"}` }
	if err := st.BeginRun("r1", 1, 10); err != nil {
		t.Fatal(err)
	}
	see("http://app.test/removed", page("http://app.test/removed"))
	see("http://app.test/kept", page("http://app.test/kept"))
	if err := st.BeginRun("r2", 1, 10); err != nil {
		t.Fatal(err)
	}
	see("http://app.test/kept", page("http://app.test/kept"))
	see("http://app.test/fresh", page("http://app.test/fresh"))
	see("http://app.test/catchall", `{"url":"http://app.test/catchall","status":200,"catchall":true}`)
	see("http://app.test/bundle", `{"url":"http://app.test/bundle","status":200,"role":"script"}`)
	see("http://app.test/logo", `{"url":"http://app.test/logo","status":200,"role":"asset"}`)
	see("http://app.test/bundle.map", `{"url":"http://app.test/bundle.map","status":200,"role":"sourcemap"}`)
	see("http://app.test/app.js", page("http://app.test/app.js"))
	see("http://app.test/logo.png", page("http://app.test/logo.png"))
	see("http://app.test/app.js.map", page("http://app.test/app.js.map"))
	see("new.app.test", `{"fqdn":"new.app.test","ips":["192.0.2.1"]}`)
	st.Close()
	got := strings.Join(newRows(t, db), " ")
	if want := "http://app.test/fresh http://app.test/kept new.app.test"; got != want {
		t.Errorf("new lists %q, want %q: not the page the newest run did not see, a catch-all answer, a script, an asset, a source map, or an address that says so", got, want)
	}
}
