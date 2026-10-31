package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func portsServer(t *testing.T) (port string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Werkzeug/2.2.3 Python/3.11")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>lab</title></html>")
	}))
	t.Cleanup(srv.Close)
	_, port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return port
}

func hostsFile(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// run -ports gives each open port a row of its own, as ports does, and
// -probe goes on to the web service found there: the 443 and 80 guessed for
// a bare address, with nothing listening, are a note and not a failure.
func TestRunPortsRowsAndProbeOfFoundServices(t *testing.T) {
	port := portsServer(t)
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "run", "-list", hostsFile(t, "127.0.0.1"), "-ports", port, "-probe", "-sources", "none", "-db", "p.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v unreachable %v notes %q", code, rep.Failed, rep.Unreachable, rep.Notes)
	}
	var portRow, webRow bool
	for _, r := range jsonRows(t, out) {
		switch key, _ := r["key"].(string); {
		case r["type"] == "Port" && key == "127.0.0.1:"+port+"/tcp":
			portRow = r["service"] == "http"
		case key == "http://127.0.0.1:"+port+"/":
			webRow = r["coverage"] == "visited"
		case key == "https://127.0.0.1/":
			t.Errorf("a guessed https://127.0.0.1/ has a row: %v", r)
		}
	}
	if !portRow {
		t.Errorf("no port row with its service:\n%s", out)
	}
	if !webRow {
		t.Errorf("the web service on the open port was not probed:\n%s", out)
	}
	if rep.Counts["ports"] != 1 {
		t.Errorf("counts %v lack the port", rep.Counts)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "no web service on 443 or 80") {
		t.Errorf("notes %q lack the no-web-service note", rep.Notes)
	}
}

// -web-ports names where a bare address's web service is: those ports are
// asked and not 443 or 80, and a port asked that refuses is a failure.
func TestRunWebPortsOfABareAddress(t *testing.T) {
	port := portsServer(t)
	shut, _ := net.Listen("tcp", "127.0.0.1:0")
	_, shutPort, _ := net.SplitHostPort(shut.Addr().String())
	shut.Close()
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, "run", "-list", hostsFile(t, "127.0.0.1"), "-web-ports", port, "-probe", "-sources", "none", "-db", "w.db")
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	if !strings.Contains(out, `"key":"http://127.0.0.1:`+port+`/"`) || !strings.Contains(out, `"coverage":"visited"`) {
		t.Errorf("-web-ports %s was not probed:\n%s", port, out)
	}
	if strings.Contains(out, `"key":"https://127.0.0.1/"`) || strings.Contains(out, "no web service") {
		t.Errorf("443 or 80 were guessed beside -web-ports:\n%s", out)
	}
	_, rep, code = runContract(t, "run", "-list", hostsFile(t, "127.0.0.1"), "-web-ports", shutPort, "-probe", "-sources", "none", "-db", "w2.db")
	if code != exitPartial || len(rep.Unreachable) == 0 {
		t.Errorf("a -web-ports port nothing listens on: exit %d, unreachable %v", code, rep.Unreachable)
	}
}
