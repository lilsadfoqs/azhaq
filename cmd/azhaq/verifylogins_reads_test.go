package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
)

// ShowDoc's published account, end to end: the two controls and the pair are
// three POSTs, the session is ended with the product's logout, all four are
// ledger lines of azhaq-verify-logins, and the password is nowhere in the
// output.
func TestVerifyLoginsShowDocDefaultIsProvedAndLoggedOut(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "ShowDoc/3.2.0", func(n int, w http.ResponseWriter, r *http.Request) {
		switch r.URL.RequestURI() {
		case "/server/index.php?s=/api/user/login":
			r.ParseForm()
			switch {
			case r.Form.Get("password") == "":
				w.Write([]byte(`{"error_code":10206,"error_message":"no empty password"}`))
			case r.Form.Get("username") == "showdoc" && r.Form.Get("password") == "123456":
				w.Header().Set("Set-Cookie", "cookie_token=tok; Path=/")
				w.Write([]byte(`{"error_code":0,"data":{"username":"showdoc","user_token":"tok"}}`))
			default:
				w.Write([]byte(`{"error_code":10210,"error_message":"username or password incorrect"}`))
			}
		case "/server/index.php?s=/api/user/logout":
			w.Write([]byte(`{"error_code":0}`))
		default:
			w.Write([]byte("<html>front page</html>"))
		}
	})
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	var logins, logouts int
	for _, r := range fx.requests() {
		switch {
		case strings.HasPrefix(r, "POST /server/index.php?s=/api/user/login"):
			logins++
		case strings.HasPrefix(r, "POST /server/index.php?s=/api/user/logout"):
			logouts++
		}
	}
	if logins != 3 || logouts != 1 {
		t.Errorf("%d sign-in POSTs and %d logouts, want 3 and 1: %v", logins, logouts, fx.requests())
	}
	f := loginFindingOf(t, db, "default-login")
	if f.Label != "proved" && !strings.Contains(strings.ToLower(out+errOut), "proved") {
		t.Errorf("finding %+v is not proved", f)
	}
	if strings.Contains(out+errOut, "123456") {
		t.Error("the password is in the output")
	}
	n := 0
	if err := ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
		if e.Collector == "azhaq-verify-logins" && e.Kind == "http" {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("%d azhaq-verify-logins http lines, want 4 (two controls, the pair, the logout)", n)
	}
}

// OpenTSDB's two reads, end to end: four GETs (each read with no credential
// and with a wrong one), two stored findings, each a request of the budget.
func TestVerifyLoginsOpenTSDBReadsAreFoundAndCounted(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "OpenTSDB/2.4.1", func(n int, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/config":
			w.Write([]byte(`{"tsd.network.port":"4242","tsd.core.auto_create_metrics":"true"}`))
		case "/api/stats":
			w.Write([]byte(`[{"metric":"tsd.connectionmgr.connections","timestamp":1,"value":"1","tags":{"host":"h"}}]`))
		default:
			w.Write([]byte("<html>front page</html>"))
		}
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db, "-verify-logins")) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	got := map[string]int{}
	for _, r := range fx.requests() {
		if strings.HasPrefix(r, "GET /api/config") || strings.HasPrefix(r, "GET /api/stats") {
			got[strings.Fields(r)[1]]++
		}
	}
	if got["/api/config"] != 2 || got["/api/stats"] != 2 {
		t.Errorf("requests %v, want two GETs of each", got)
	}
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	stored, _ := st.Observations()
	paths := map[string]bool{}
	for _, r := range verifyResultsOf(stored) {
		if r.Kind == verify.KindUnauthenticatedBypass && r.Label == verify.Proved {
			paths[strings.TrimPrefix(r.URL, fx.URL)] = true
		}
	}
	if !paths["/api/config"] || !paths["/api/stats"] {
		t.Errorf("stored findings %v, want both reads", paths)
	}
}
