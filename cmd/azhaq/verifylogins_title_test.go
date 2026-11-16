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

// A console that only its Basic realm names (a 401 on the front page, a Jetty
// Server header, no title, no technology) is asked its product's published
// default like any other: the realm is a name the catalog reads.
func TestVerifyLoginsAsksAProductNamedOnlyByItsRealm(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Jetty(9.4.51.v20230217)", func(n int, w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == "admin" && p == "admin" && strings.HasPrefix(r.URL.Path, "/admin") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>Apache ActiveMQ Console</body></html>"))
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="ActiveMQRealm"`)
		w.WriteHeader(401)
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	f := loginFindingOf(t, db, "default-login")
	if f.Product != "ActiveMQ" || f.Label != "proved" {
		t.Errorf("finding %+v", f)
	}
	rep := lastReport(t, errOut)
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "verify-logins: 1 product(s) asked") {
		t.Errorf("notes %q", rep.Notes)
	}
}

// A host with exactly one confirmed product the catalog lists (on a service
// that is not a web one) and a web service nothing names is offered as a lead
// in the summary: nothing is sent for it. Two such products, or a web service
// that names a catalog product of its own, leave no lead.
func TestVerifyLoginsLeadsOneConfirmedProductToUnnamedWebServices(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obsOf := func(services ...map[string]any) []types.StoredObservation {
		payload, _ := json.Marshal(map[string]any{"host": "mq.example.test", "ip": "192.0.2.10", "services": services})
		return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: payload}}}
	}
	broker := map[string]any{"port": 61616, "service": "openwire", "product": "ActiveMQ", "version": "5.18.3"}
	console := map[string]any{"port": 8161, "service": "http", "product": "Jetty", "version": "9.4.51"}
	_, _, note := loginsStage(context.Background(), st, obsOf(broker, console), "azhaq ports")
	if !strings.Contains(note, "leads, not matches (nothing was sent for them): ActiveMQ is confirmed on mq.example.test:61616 and the host's web service mq.example.test:8161 (Jetty)") {
		t.Errorf("note %q", note)
	}
	rabbit := map[string]any{"port": 5672, "service": "amqp", "product": "RabbitMQ", "version": "3.12.0"}
	if _, _, note := loginsStage(context.Background(), st, obsOf(broker, rabbit, console), "azhaq ports"); strings.Contains(note, "leads, not matches") {
		t.Errorf("two catalog products on the host gave a lead: %q", note)
	}
}

// The published pair is admin:admin and the console lives under /admin/: the
// evidence of the proved login keeps /admin/queues.jsp and the page's own
// words, and masks only the password where the page echoes it as one.
func TestVerifyLoginsEvidenceKeepsAPathThatHoldsThePassword(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Jetty(9.4.51.v20230217)", func(n int, w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == "admin" && p == "admin" && strings.HasPrefix(r.URL.Path, "/admin") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><title>Apache ActiveMQ Console</title><a href="/admin/queues.jsp">Queues</a> password=admin</html>`))
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="ActiveMQRealm"`)
		w.WriteHeader(401)
	})
	db := filepath.Join(t.TempDir(), "w.db")
	if _, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) }); err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	f := loginFindingOf(t, db, "default-login")
	if !strings.Contains(f.Proof.Excerpt, `href="/admin/queues.jsp"`) || !strings.Contains(f.Proof.Excerpt, "password=(the published default)") || strings.Contains(f.Proof.Excerpt, "password=admin") {
		t.Errorf("excerpt %q", f.Proof.Excerpt)
	}
}
