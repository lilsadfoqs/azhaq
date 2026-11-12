package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// loginsNextLines are the summary's next-pass lines that name -verify-logins.
func loginsNextLines(rep report) []string {
	var out []string
	for _, l := range rep.Next {
		if strings.Contains(l, "-verify-logins") {
			out = append(out, l)
		}
	}
	return out
}

// A run that identified a product the default-login catalog lists, without
// -verify-logins, names it as a next pass: how many services, what it would send
// (one sign-in attempt with the published default pair, every request in the
// ledger) and the command. Nothing is sent for it.
func TestRunNamesVerifyLoginsWhenACatalogProductWasIdentified(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>front page</html>"))
	})
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error { return cmdRun(loginsRunArgs(fx.URL+"/", db)) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	lines := loginsNextLines(lastReport(t, errOut))
	if len(lines) != 1 {
		t.Fatalf("want one -verify-logins next line: %q", lastReport(t, errOut).Next)
	}
	l := lines[0]
	for _, want := range []string{"azhaq run -url " + fx.URL + "/", "-verify-logins", "-db " + db, "next pass, not run", "1 service found with a product in the default-login catalog (Harbor)",
		"1 sign-in attempt, one for each product on each service, with its published default credential pair", "every request is a line of the ledger"} {
		if !strings.Contains(l, want) {
			t.Errorf("the line lacks %q: %s", want, l)
		}
	}
	for _, r := range fx.requests() {
		if strings.Contains(r, "auth=Basic") {
			t.Errorf("the run sent a credential: %s", r)
		}
	}
}

// With -verify-logins given, or when no product named is in the catalog, there
// is no such line.
func TestRunDoesNotNameVerifyLoginsWhenItWasGivenOrNothingIsInTheCatalog(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	harbor := newLoginFixture(t, "Harbor/2.9.0", func(n int, w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	foo := newLoginFixture(t, "Foo/1.0", func(n int, w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>Welcome</title></head></html>"))
	})
	for name, args := range map[string][]string{
		"flag given":     loginsRunArgs(harbor.URL+"/", filepath.Join(t.TempDir(), "a.db"), "-verify-logins"),
		"not in catalog": loginsRunArgs(foo.URL+"/", filepath.Join(t.TempDir(), "b.db")),
	} {
		_, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
		if err != nil {
			t.Fatalf("%s: run: %v\n%s", name, err, errOut)
		}
		if lines := loginsNextLines(lastReport(t, errOut)); len(lines) != 0 {
			t.Errorf("%s: no next line names -verify-logins: %q", name, lines)
		}
	}
}

// A product only a name's root page names (a title on a shared listener) counts
// as one service, on its name's origin, with the same line.
func TestRunNamesVerifyLoginsForAProductNamedByAPageTitle(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	lab := newNamesLabPages(t, map[string]string{
		"grafana." + namesZone: `<html><head><title>Grafana</title></head><body>sign in</body></html>`,
	})
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, append([]string{"run"}, lab.urlArgs("-db", "apps.db", "-no-paths", "-no-favicon")...)...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	lines := loginsNextLines(rep)
	if len(lines) != 1 || !strings.Contains(lines[0], "1 service found with a product in the default-login catalog (Grafana)") {
		t.Errorf("next lines %q", rep.Next)
	}
}
