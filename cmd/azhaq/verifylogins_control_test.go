package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// brokerFixture is a message-broker console: the front page and /admin/ are
// public, /admin/queues.jsp needs the Basic pair given.
func brokerFixture(t *testing.T, user, pass string, gated bool) *loginFixture {
	t.Helper()
	return newLoginFixture(t, "", func(n int, w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, `<html><title>Apache ActiveMQ</title><body>Welcome to the Apache ActiveMQ!</body></html>`)
		case r.URL.Path == "/admin/":
			fmt.Fprint(w, `<html><title>Apache ActiveMQ Console</title><body>Welcome to the Apache ActiveMQ Console</body></html>`)
		case r.URL.Path == "/admin/queues.jsp" && (!gated || ok && u == user && p == pass):
			fmt.Fprint(w, `<html><title>Queues</title>queues</html>`)
		case r.URL.Path == "/admin/queues.jsp":
			w.Header().Set("WWW-Authenticate", `Basic realm="ActiveMQRealm"`)
			w.WriteHeader(401)
		default:
			w.WriteHeader(404)
		}
	})
}

func pairSent(fx *loginFixture, user, pass string) bool {
	want := "auth=Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	for _, r := range fx.requests() {
		if strings.HasSuffix(r, want) {
			return true
		}
	}
	return false
}

func hitsOf(fx *loginFixture, prefix string) int {
	n := 0
	for _, r := range fx.requests() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func runLogins(t *testing.T, fx *loginFixture, db string, extra ...string) (string, report) {
	t.Helper()
	// The detection templates name the console, so they stay on.
	args := append([]string{"-url", fx.URL + "/", "-db", db, "-json", "-depth", "0", "-no-paths", "-no-favicon", "-no-takeover"}, extra...)
	out, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	return out, lastReport(t, errOut)
}

// A console whose public pages answer 200 and whose password was changed is no
// default login (#548): a row only where the pair changes the answer.
func TestVerifyLoginsPublicConsoleWithAChangedPasswordIsNotProved(t *testing.T) {
	for name, gated := range map[string]bool{"gated pages refuse the pair": true, "every page is public": false} {
		t.Run(name, func(t *testing.T) {
			egress.Reset()
			t.Cleanup(egress.Reset)
			fx := brokerFixture(t, "admin", "S3cr3t-changed", gated)
			out, rep := runLogins(t, fx, filepath.Join(t.TempDir(), "w.db"), "-verify-logins")
			for _, r := range verifyRowsOf(t, out) {
				if r["kind"] == "default-login" {
					t.Errorf("proved from a page that needs no password: %v", r)
				}
			}
			if len(rep.Verify) != 0 {
				t.Errorf("summary verify=%v", rep.Verify)
			}
			if !gated {
				if pairSent(fx, "admin", "admin") {
					t.Error("the published pair was sent to a page open to all")
				}
				if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "the page answers the same without a credential; the published pair was not proved") {
					t.Errorf("no note for the open page: %q", rep.Notes)
				}
			}
		})
	}
}

// The same console with the default pair on its gated page: proved, with the
// control outcome beside the pair's and both requests in the command; every
// request is a ledger line and in the run's count.
func TestVerifyLoginsControlsAreInTheProofTheLedgerAndTheCount(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := brokerFixture(t, "admin", "admin", true)
	dbOff := filepath.Join(t.TempDir(), "off.db")
	_, repOff := runLogins(t, fx, dbOff)
	egress.Reset()
	before := hitsOf(fx, "GET /admin/queues.jsp")
	db := filepath.Join(t.TempDir(), "w.db")
	out, rep := runLogins(t, fx, db, "-verify-logins")
	var row map[string]any
	for _, r := range verifyRowsOf(t, out) {
		if r["kind"] == "default-login" {
			row = r
		}
	}
	if row == nil || row["label"] != "proved" || row["url"] != fx.URL+"/admin/queues.jsp" {
		t.Fatalf("row %v\n%s", row, out)
	}
	if ev, _ := row["evidence"].(string); !strings.Contains(ev, "no credential: 401; wrong pair: 401; the published pair (admin): 200 + marker") {
		t.Errorf("evidence %q", ev)
	}
	f := loginFindingOf(t, db, "default-login")
	if !strings.Contains(f.Proof.Excerpt, "no credential: 401; wrong pair: 401") || strings.Count(f.Proof.Reproduce, "curl ") != 3 || strings.Contains(f.Proof.Reproduce, "admin:admin") {
		t.Errorf("proof %+v", f.Proof)
	}
	if got := hitsOf(fx, "GET /admin/queues.jsp") - before; got != 3 {
		t.Errorf("the fixture saw %d requests of the sign-in, want the two controls and the pair", got)
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
	if n != 3 {
		t.Errorf("%d ledger lines of azhaq-verify-logins, want 3", n)
	}
	if d := rep.Requests - repOff.Requests; d != 3 {
		t.Errorf("the run sent %d requests more with -verify-logins, want 3", d)
	}
}

// A form login whose refusal redirects as well is proved only where the
// redirect goes elsewhere for the pair than for the wrong credential.
func TestVerifyLoginsFormLoginThatRedirectsEitherWay(t *testing.T) {
	for name, tc := range map[string]struct {
		good  string
		proof bool
	}{"the pair lands on the home page": {"/menu/home", true}, "every sign-in lands on the error page": {"/user/error", false}} {
		t.Run(name, func(t *testing.T) {
			egress.Reset()
			t.Cleanup(egress.Reset)
			fx := newLoginFixture(t, "Rundeck/4.17.0", func(n int, w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/j_security_check" {
					r.ParseForm()
					to := "/user/error"
					if r.Form.Get("j_username") == "admin" && r.Form.Get("j_password") == "admin" {
						to = tc.good
					}
					w.Header().Set("Location", to)
					w.WriteHeader(302)
					return
				}
				fmt.Fprint(w, `<html><title>Rundeck - Login</title></html>`)
			})
			out, _ := runLogins(t, fx, filepath.Join(t.TempDir(), "w.db"), "-verify-logins")
			var found bool
			for _, r := range verifyRowsOf(t, out) {
				if r["kind"] == "default-login" {
					found = true
				}
			}
			if found != tc.proof {
				t.Errorf("proved=%v, want %v\n%s", found, tc.proof, out)
			}
			if hitsOf(fx, "POST /j_security_check") < 2 {
				t.Errorf("want the controls sent: %v", fx.requests())
			}
		})
	}
}

// The plan says what the controls add: in the sends, and in the estimate.
func TestPlanCountsTheLoginControls(t *testing.T) {
	p := planJSON(t, "-url", "http://127.0.0.1:3001/", "-verify-logins")
	s := strings.Join(p.Sends, "\n")
	if !strings.Contains(s, "two control requests") || !strings.Contains(s, "3 requests") {
		t.Errorf("sends do not name the controls:\n%s", s)
	}
	var found bool
	for _, st := range p.Estimate.Stages {
		if st.Stage == "verify" && strings.Contains(st.NotCounted, "3 requests per sign-in pair") {
			found = true
		}
	}
	if !found {
		t.Errorf("the estimate has no verify-logins entry: %+v", p.Estimate.Stages)
	}
}
