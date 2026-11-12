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

const foldSwagger = `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/api/user":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

// One service on a loopback address, reached as its address and as localhost,
// gives one hunt row for the API description it serves, naming the other URL
// that answered the same; the tier count and the run's own next line count the
// folded row once.
func TestHuntOneRowForAServiceReachedByAddressAndName(t *testing.T) {
	if addrs, err := net.LookupHost("localhost"); err != nil || !slices.Contains(addrs, "127.0.0.1") {
		t.Skipf("localhost does not resolve to 127.0.0.1: %v %v", addrs, err)
	}
	egress.Reset()
	t.Cleanup(egress.Reset)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><head><title>lab</title></head><body>hello</body></html>")
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, foldSwagger)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	byAddr, byName := "http://127.0.0.1:"+port, "http://localhost:"+port
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "fold.db")
	_, rep, code := runContract(t, "run", "-url", byAddr+"/", "-url", byName+"/", "-allow", "127.0.0.1:"+port, "-allow", "localhost:"+port,
		"-sources", "none", "-no-history", "-no-favicon", "-db", db)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	if !slices.ContainsFunc(rep.Next, func(l string) bool {
		return strings.HasPrefix(l, "azhaq hunt -db "+db) && strings.Contains(l, "1 finding,")
	}) {
		t.Errorf("the next hunt line counts the folded row once: %q", rep.Next)
	}
	out, errOut, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	for _, r := range jsonLines(t, out) {
		if k, _ := r["key"].(string); strings.HasSuffix(k, "/swagger.json") {
			docs = append(docs, r)
		}
	}
	if len(docs) != 1 || docs[0]["tier"] != "finding" {
		t.Fatalf("want one finding row for /swagger.json, got %v\n%s", docs, out)
	}
	key := docs[0]["key"].(string)
	other := byName + "/swagger.json"
	if key == other {
		other = byAddr + "/swagger.json"
	}
	if also, _ := docs[0]["also_at"].([]any); len(also) != 1 || also[0] != other {
		t.Errorf("the row names %v as answering the same, want [%s]", docs[0]["also_at"], other)
	}
	if got := lastReport(t, errOut).Tiers; got == nil || got.Findings != 1 {
		t.Errorf("tiers %+v, want 1 finding", got)
	}
	// The identification of the listener is one row, naming the other host.
	var idents, named int
	for _, r := range jsonLines(t, out) {
		if r["tier"] == "identification" && strings.HasSuffix(fmt.Sprint(r["key"]), ":"+port) {
			idents++
			if r["also_named"] != nil {
				named++
			}
		}
	}
	if idents > 0 && named != idents {
		t.Errorf("%d listener rows, %d name the other host:\n%s", idents, named, out)
	}
}

// Two names of one address that serve the same root page, naming one
// application, are one identification row that lists both; two names that
// serve different root pages are two rows, each with its own name.
func TestHuntFoldsNamesOfOneListenerOnlyWhenTheyAnswerTheSame(t *testing.T) {
	for _, tc := range []struct {
		name         string
		wiki         string
		want         int
		wantAlsoName bool
	}{
		{"same page", `<html><head><title>Grafana</title></head><body>sign in</body></html>`, 1, true},
		{"different page", `<html><head><title>Grafana</title></head><body>another instance</body></html>`, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			egress.Reset()
			t.Cleanup(egress.Reset)
			lab := newNamesLabPages(t, map[string]string{
				"grafana." + namesZone: `<html><head><title>Grafana</title></head><body>sign in</body></html>`,
				"wiki." + namesZone:    tc.wiki,
			})
			t.Chdir(t.TempDir())
			db := "apps.db"
			_, rep, code := runContract(t, append([]string{"run"}, lab.urlArgs("-db", db, "-no-paths", "-no-favicon")...)...)
			if code != exitOK && code != exitPartial {
				t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
			}
			out, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
			if err != nil {
				t.Fatal(err)
			}
			var rows []map[string]any
			for _, r := range jsonLines(t, out) {
				if r["tier"] == "identification" && r["product"] == "Grafana" && fmt.Sprint(r["port"]) == lab.port {
					rows = append(rows, r)
				}
			}
			if len(rows) != tc.want {
				t.Fatalf("%d Grafana rows, want %d:\n%s", len(rows), tc.want, out)
			}
			if tc.wantAlsoName {
				if also, _ := rows[0]["also_named"].([]any); len(also) != 1 {
					t.Errorf("the row names the other host: %v", rows[0])
				}
			}
			for _, r := range rows {
				if !tc.wantAlsoName && r["also_named"] != nil {
					t.Errorf("a name serving another page is its own row: %v", r)
				}
			}
		})
	}
}
