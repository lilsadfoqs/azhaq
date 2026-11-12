package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/store"
)

// loginFixture is a stand-in web service: it sets the Server header
// given (so the crawl's own Server-header reading names its product,
// with no wappalyzer fingerprint needed) and records every request it
// gets, then hands it to serve.
type loginFixture struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []string
	n    int
}

func newLoginFixture(t *testing.T, serverHeader string, serve func(n int, w http.ResponseWriter, r *http.Request)) *loginFixture {
	t.Helper()
	f := &loginFixture{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.n++
		n := f.n
		f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI()+" auth="+r.Header.Get("Authorization"))
		f.mu.Unlock()
		if serverHeader != "" {
			w.Header().Set("Server", serverHeader)
		}
		serve(n, w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *loginFixture) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

// runArgs is the flag set every -verify-logins test runs with, besides
// the test's own: a minimal crawl of the one page, so only the checks
// under test talk to the fixture.
func loginsRunArgs(url, db string, extra ...string) []string {
	args := []string{"-url", url, "-db", db, "-json", "-depth", "0", "-no-paths", "-no-tech", "-no-favicon", "-no-takeover"}
	return append(args, extra...)
}

func verifyRowsOf(t *testing.T, out string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, line := range strings.Split(out, "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		if row["type"] == "verify" {
			rows = append(rows, row)
		}
	}
	return rows
}

// A fixture that takes Harbor's published default: one sign-in attempt,
// a proved default-login finding, the request and an excerpt as its
// evidence.
func TestVerifyLoginsAcceptedFixtureIsAProvedFinding(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/users/current" {
			u, p, ok := r.BasicAuth()
			if ok && u == "admin" && p == "Harbor12345" {
				w.WriteHeader(200)
				w.Write([]byte(`{"username":"admin","sysadmin_flag":true}`))
				return
			}
			w.WriteHeader(401)
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	rows := verifyRowsOf(t, out)
	var found map[string]any
	for _, r := range rows {
		if r["kind"] == "default-login" {
			found = r
		}
	}
	if found == nil {
		t.Fatalf("no default-login row in output:\n%s\nstderr:\n%s", out, errOut)
	}
	if found["label"] != "proved" || found["product"] != "Harbor" || found["severity"] != "critical" {
		t.Errorf("default-login row %v, want proved Harbor, critical", found)
	}
	req, _ := found["request"].(string)
	if !strings.Contains(req, "the published default credential pair") || strings.Contains(req, "Harbor12345") {
		t.Errorf("request %q must name the published default and never the password", req)
	}
	rep := lastReport(t, errOut)
	if len(rep.Verify) != 1 {
		t.Fatalf("summary verify=%v, want exactly 1 result", rep.Verify)
	}
	var hits int
	for _, r := range fx.requests() {
		if strings.HasPrefix(r, "GET /api/v2.0/users/current") {
			hits++
		}
	}
	if hits != 1 {
		t.Errorf("fixture saw %d sign-in attempts, want exactly 1 (Harbor has one published pair)", hits)
	}
}

// The same fixture, refusing the pair: no default-login row at all.
func TestVerifyLoginsRefusedFixtureIsNoFinding(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/users/current" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	for _, r := range verifyRowsOf(t, out) {
		if r["kind"] == "default-login" {
			t.Errorf("a refused pair must never be a finding: %v", r)
		}
	}
	rep := lastReport(t, errOut)
	if len(rep.Verify) != 0 {
		t.Errorf("summary verify=%v, want none", rep.Verify)
	}
}

// A 429 on the one sign-in attempt is a lockout sign: the run does not
// treat it as a failure, and (since the loop stops there) no further
// credentialed request is ever sent to that resource.
func TestVerifyLogins429StopsAndIsNotAFailure(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/users/current" {
			w.WriteHeader(429)
			w.Write([]byte("too many requests"))
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	for _, r := range verifyRowsOf(t, out) {
		if r["kind"] == "default-login" {
			t.Errorf("a 429 must never be a finding: %v", r)
		}
	}
	rep := lastReport(t, errOut)
	if len(rep.Failed) != 0 {
		t.Errorf("a lockout sign is a note, not a failure: %v", rep.Failed)
	}
	var hits int
	for _, r := range fx.requests() {
		if strings.HasPrefix(r, "GET /api/v2.0/users/current") {
			hits++
		}
	}
	if hits != 1 {
		t.Errorf("fixture saw %d credentialed requests after the 429, want exactly 1 (no second attempt)", hits)
	}
}

// A captcha on the sign-in page: the page is read (a GET), but no
// credential is ever sent — the fixture fails the test itself if a POST
// of the sign-in endpoint ever reaches it.
func TestVerifyLoginsCaptchaNeverSendsACredential(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "pfSense/2.7.2", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			if r.Method == http.MethodPost {
				t.Error("a credential was posted to a captcha-protected sign-in page")
			}
			w.Write([]byte(`<form><input type="hidden" name="login_captcha"><input class="g-recaptcha"></form>`))
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	for _, r := range verifyRowsOf(t, out) {
		if r["kind"] == "default-login" {
			t.Errorf("a captcha-protected page must never be a finding: %v", r)
		}
	}
	var posts, gets int
	for _, r := range fx.requests() {
		switch {
		case strings.HasPrefix(r, "POST /index.php"):
			posts++
		case strings.HasPrefix(r, "GET /index.php"):
			gets++
		}
	}
	if posts != 0 {
		t.Errorf("want zero POSTs to the sign-in page, got %d", posts)
	}
	if gets == 0 {
		t.Error("want the sign-in page read once (to look for a captcha), got none")
	}
}

// Unauthenticated reads: a resource that shows the protected content
// with no credential is a finding; one that shows a login is not —
// whatever the wrong-credential answer shows.
func TestVerifyLoginsUnauthenticatedReadShowsContentVsLogin(t *testing.T) {
	t.Run("shows the protected content: a finding", func(t *testing.T) {
		egress.Reset()
		t.Cleanup(egress.Reset)
		fx := newLoginFixture(t, "Elasticsearch/7.17.0", func(n int, w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_cluster/health" {
				w.Write([]byte(`{"cluster_name":"prod-cluster","status":"green"}`))
				return
			}
			w.Write([]byte("<html>front page</html>"))
		})
		db := filepath.Join(t.TempDir(), "w.db")
		out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
		if err != nil {
			t.Fatalf("run: %v\n%s", err, errOut)
		}
		var found map[string]any
		for _, r := range verifyRowsOf(t, out) {
			if r["kind"] == "unauthenticated-bypass" {
				found = r
			}
		}
		if found == nil {
			t.Fatalf("no unauthenticated-bypass row:\n%s", out)
		}
		if found["label"] != "proved" || found["severity"] != "high" {
			t.Errorf("row %v, want proved, high", found)
		}
		var hits int
		for _, r := range fx.requests() {
			if strings.HasPrefix(r, "GET /_cluster/health") {
				hits++
			}
		}
		if hits != 2 {
			t.Errorf("want 2 reads (no credential, then a wrong one), got %d", hits)
		}
	})
	t.Run("shows a login unauthenticated: no finding", func(t *testing.T) {
		egress.Reset()
		t.Cleanup(egress.Reset)
		fx := newLoginFixture(t, "Elasticsearch/7.17.0", func(n int, w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_cluster/health" {
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"missing authentication credentials"}`))
				return
			}
			w.Write([]byte("<html>front page</html>"))
		})
		db := filepath.Join(t.TempDir(), "w.db")
		out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
		if err != nil {
			t.Fatalf("run: %v\n%s", err, errOut)
		}
		for _, r := range verifyRowsOf(t, out) {
			if r["kind"] == "unauthenticated-bypass" {
				t.Errorf("a gated resource must never be a finding: %v", r)
			}
		}
	})
}

// Every request -verify-logins makes is a ledger line of the collector
// azhaq-verify-logins.
func TestVerifyLoginsRequestsAreLedgerLines(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/users/current" {
			w.WriteHeader(200)
			w.Write([]byte(`{"username":"admin"}`))
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	n := 0
	if err := ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
		if e.Collector == "azhaq-verify-logins" {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("want at least one ledger line of the collector azhaq-verify-logins")
	}
}

// The flag off: the fixture never sees the credentialed request at all,
// even though its Server header names a cataloged product.
func TestVerifyLoginsFlagOffSendsNothing(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/users/current" {
			w.WriteHeader(200)
			w.Write([]byte(`{"username":"admin"}`))
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db)) }) // no -verify-logins
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	if rows := verifyRowsOf(t, out); len(rows) != 0 {
		t.Errorf("want no verify rows with the flag off, got %v", rows)
	}
	for _, r := range fx.requests() {
		if strings.Contains(r, "auth=Basic") || strings.HasPrefix(r, "GET /api/v2.0/users/current") {
			t.Errorf("a credentialed request was sent although -verify-logins was not given: %q", r)
		}
	}
}

// A password is never printed or stored: not in stdout, not in stderr,
// not in the workspace, not in the ledger.
func TestVerifyLoginsPasswordNeverAppearsAnywhere(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	const password = "Harbor12345"
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2.0/users/current" {
			_, p, ok := r.BasicAuth()
			if ok && p == password {
				w.WriteHeader(200)
				w.Write([]byte(`{"username":"admin"}`))
				return
			}
			w.WriteHeader(401)
			return
		}
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	if strings.Contains(out, password) || strings.Contains(errOut, password) {
		t.Fatal("the password leaked into stdout or stderr")
	}
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if strings.Contains(string(o.Payload), password) {
			t.Fatalf("the password leaked into a stored observation: %s", o.Payload)
		}
	}
	ledgerRaw, err := os.ReadFile(db + ".ledger.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ledgerRaw), password) {
		t.Fatal("the password leaked into the ledger")
	}
}

// A Form-mode success (Rundeck) leaves a session a product has a logout
// for: the check ends it with that logout request, best-effort.
func TestVerifyLoginsSendsLogoutAfterASuccess(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Rundeck/4.17.0", func(n int, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/j_security_check":
			r.ParseForm()
			if r.Form.Get("j_username") == "admin" && r.Form.Get("j_password") == "admin" {
				w.Header().Set("Set-Cookie", "JSESSIONID=test-session")
				w.WriteHeader(200)
				w.Write([]byte("rundeck dashboard"))
				return
			}
			w.WriteHeader(401)
		case r.URL.Path == "/logout":
			w.WriteHeader(200)
		default:
			w.Write([]byte("<html>front page</html>"))
		}
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	var sawLogout bool
	for _, r := range fx.requests() {
		if strings.HasPrefix(r, "GET /logout") {
			sawLogout = true
		}
	}
	if !sawLogout {
		t.Errorf("want a logout request after the success, fixture saw: %v", fx.requests())
	}
}
