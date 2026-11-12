package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// A catalog product that only its login page's <title> names (the front page
// redirects to /login, no Server header, no technology rows) is asked like any
// other: one sign-in attempt with the published default, a proved finding
// where the stub takes it, and the summary counts the product.
func TestVerifyLoginsAsksAProductNamedOnlyByItsTitle(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "", func(n int, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Grafana</title></head><body><script>window.grafanaBootData={settings:{buildInfo:{version:"10.2.0"}}}</script></body></html>`))
		case "/api/org":
			if u, p, ok := r.BasicAuth(); ok && u == "admin" && p == "admin" {
				w.Write([]byte(`{"id":1,"name":"Main Org."}`))
				return
			}
			w.WriteHeader(401)
		default:
			w.WriteHeader(404)
		}
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	f := loginFindingOf(t, db, "default-login")
	if f.Product != "Grafana" || f.Label != "proved" {
		t.Errorf("finding %+v", f)
	}
	rep := lastReport(t, errOut)
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "verify-logins: 1 product(s) asked") || strings.Contains(notes, "none asked") {
		t.Errorf("notes %q", rep.Notes)
	}
}

// A zero is never left unexplained: when the run names no product the catalog
// has, the summary says what it named; a catalog product named by a service
// that is not a web one is named with why nothing was sent for it.
func TestVerifyLoginsExplainsWhatItDidNotAsk(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Foo/1.0", func(n int, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>Welcome</title></head></html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "0 product(s) asked") || !strings.Contains(notes, "none asked: no product the run named is in the catalog (1 product named: Foo)") {
		t.Errorf("notes %q", rep.Notes)
	}

	// Neo4j named by the banner of a port that is not a web one.
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	payload, _ := json.Marshal(map[string]any{"host": "db.example.test", "ip": "192.0.2.10", "services": []map[string]any{{"port": 7687, "service": "bolt", "product": "Neo4j", "version": "5.1"}}})
	obs := []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: payload}}}
	_, _, note := loginsStage(context.Background(), st, obs, "azhaq ports")
	if !strings.Contains(note, "0 product(s) asked") || !strings.Contains(note, "not asked: Neo4j on db.example.test:7687 (named by its banner) has no web origin") {
		t.Errorf("note %q", note)
	}
}
