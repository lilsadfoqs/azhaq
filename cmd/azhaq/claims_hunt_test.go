package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// hunt reads the workspace and the -roles files and sends nothing: not a
// request to the site the map came from, not a DNS
// query, and it writes no ledger.
func TestHuntSendsNothing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><title>x</title><a href="/admin">a</a><a href="/files/backup.sql">b</a></html>`))
	}))
	defer srv.Close()
	work := t.TempDir()
	t.Chdir(work)
	db := filepath.Join(work, "w.db")
	if _, _, err := captureBoth(t, func() error { return cmdRun([]string{"-url", srv.URL + "/", "-db", db, "-json"}) }); err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("the run sent nothing: the test shows nothing")
	}
	roles := filepath.Join(work, "roles.jsonl")
	if err := os.WriteFile(roles, []byte(`{"url":"`+srv.URL+`/admin","verdict":"reads another role's object","confidence":"proved"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, files := hits.Load(), globNames(t, work)
	sent, dnsSent, total := egress.Sent(), egress.DNSTotal(), egress.Total()
	out, errOut, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-roles", roles, "-json"}) })
	if err != nil || len(lines(out)) == 0 {
		t.Fatalf("%v, %d rows\n%s", err, len(lines(out)), errOut)
	}
	rep := sumMap(t, errOut)
	if hits.Load() != before || egress.Sent() != sent || egress.DNSTotal() != dnsSent || egress.Total() != total || rep["requests"] != float64(0) {
		t.Errorf("hunt sent: %d more requests to the site, summary requests %v", hits.Load()-before, rep["requests"])
	}
	if now := globNames(t, work); strings.Join(now, " ") != strings.Join(files, " ") {
		t.Errorf("hunt wrote files: %v before, %v after", files, now)
	}
}

func globNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}
