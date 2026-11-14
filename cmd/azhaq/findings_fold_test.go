package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// foldLab serves one application that a run reaches as its address and as
// localhost: a dashboard its own title names (a finding), an admin path whose
// answer does not show a panel (a lead), an API description (a lead) and a
// script that names a route.
func foldLab(t *testing.T) (db, byAddr, byName string) {
	t.Helper()
	if addrs, err := net.LookupHost("localhost"); err != nil || !slices.Contains(addrs, "127.0.0.1") {
		t.Skipf("localhost does not resolve to 127.0.0.1: %v %v", addrs, err)
	}
	egress.Reset()
	t.Cleanup(egress.Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>lab</title></head><body><a href="/dashboard">d</a> <a href="/admin">a</a></body></html>`)
		case "/dashboard", "/admin":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>Dashboard</title></head><body>ops dashboard</body></html>")
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, foldSwagger)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	byAddr, byName = "http://127.0.0.1:"+port, "http://localhost:"+port
	t.Chdir(t.TempDir())
	db = filepath.Join(t.TempDir(), "fold.db")
	_, rep, code := runContract(t, "run", "-url", byAddr+"/", "-url", byName+"/", "-allow", "127.0.0.1:"+port, "-allow", "localhost:"+port,
		"-sources", "none", "-no-history", "-no-favicon", "-db", db)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	return db, byAddr, byName
}

// One service reached by its address and by a name that resolves to it is one
// finding in `report -findings` and in `export -format findings`, as it is one
// row in hunt, with the other URL in also_at.
func TestFindingsOneRecordForAServiceReachedByAddressAndName(t *testing.T) {
	db, byAddr, byName := foldLab(t)
	for name, get := range map[string]func() (string, error){
		"report": func() (string, error) {
			out, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl"}) })
			return out, err
		},
		"export": func() (string, error) {
			out, _, err := captureBoth(t, func() error { return run([]string{"export", "-db", db, "-format", "findings"}) })
			return out, err
		},
	} {
		out, err := get()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var panels []map[string]any
		for _, r := range jsonLines(t, out) {
			if r["type"] == "finding" && r["kind"] == "exposed-panel" {
				panels = append(panels, r)
			}
		}
		if len(panels) != 1 {
			t.Fatalf("%s: %d dashboard findings, want 1 (one service, two names):\n%s", name, len(panels), out)
		}
		url := panels[0]["url"].(string)
		other := byName + "/dashboard"
		if url == other {
			other = byAddr + "/dashboard"
		}
		if also, _ := panels[0]["also_at"].([]any); len(also) != 1 || also[0] != other {
			t.Errorf("%s: the finding names %v as answering the same, want [%s]", name, panels[0]["also_at"], other)
		}
	}
	// Markdown says it too.
	md, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "the same answer at "+byName+"/dashboard") && !strings.Contains(md, "the same answer at "+byAddr+"/dashboard") {
		t.Errorf("the Markdown finding does not name the other URL:\n%s", md)
	}
}
