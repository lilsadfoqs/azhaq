package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// export -format targets lists one origin for each web service that
// answered, whatever path the answer was read at; hosts and urls agree on
// which services there are.
func TestExportTargetsReducesAnswersToTheirOrigins(t *testing.T) {
	dir := t.TempDir()
	in := ingestFile(t, "httpx.jsonl",
		`{"url":"http://127.0.0.1:5002/","input":"http://127.0.0.1:5002/","scheme":"http","host":"127.0.0.1","port":"5002","path":"/","status_code":200,"failed":false}
{"url":"http://127.0.0.1:5030/login.php","input":"http://127.0.0.1:5030/login.php","scheme":"http","host":"127.0.0.1","port":"5030","path":"/login.php","status_code":200,"failed":false}
{"url":"http://127.0.0.1:5030/about?x=1","input":"http://127.0.0.1:5030/about?x=1","scheme":"http","host":"127.0.0.1","port":"5030","path":"/about","status_code":200,"failed":false}
`)
	db := filepath.Join(dir, "i.db")
	if _, errOut, err := captureBoth(t, func() error { return cmdIngest([]string{"-in", in, "-db", db}) }); err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	list := func(format string) []string {
		out, errOut, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", format}) })
		if err != nil {
			t.Fatalf("%s: %v: %s", format, err, errOut)
		}
		return strings.Fields(out)
	}
	if got, want := strings.Join(list("targets"), " "), "http://127.0.0.1:5002/ http://127.0.0.1:5030/"; got != want {
		t.Errorf("targets: %q, want %q", got, want)
	}
	if got := strings.Join(list("hosts"), " "); got != "127.0.0.1" {
		t.Errorf("hosts: %q", got)
	}
	if n := len(list("urls")); n != 3 {
		t.Errorf("urls lists %d, want the 3 answers", n)
	}
}

// A service probed at a URL with a path is a target at its origin.
func TestExportTargetsAfterProbeOfAPath(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>Login</title></html>")
	}))
	defer site.Close()
	db := filepath.Join(t.TempDir(), "p.db")
	cli(t, "probe", "-u", site.URL+"/login.php", "-allow", "127.0.0.1", "-db", db, "-ledger", "off", "-json")
	out, errOut, err := captureBoth(t, func() error { return cmdExport([]string{"-db", db, "-format", "targets"}) })
	if err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	if got := strings.TrimSpace(out); got != site.URL+"/" {
		t.Errorf("targets: %q (stderr %q), want %q", got, errOut, site.URL+"/")
	}
}
