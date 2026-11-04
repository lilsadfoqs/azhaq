package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func portNum(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A run whose request budget was not reached, and whose tasks all ran, is not
// a stopped run: it exits 0 and says nothing was left (#216).
func TestRunBudgetNotReachedIsNotStopped(t *testing.T) {
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<title>ok</title>") })
	a, b := httptest.NewServer(page), httptest.NewServer(page)
	defer a.Close()
	defer b.Close()
	closed := portNum(t, closedPort(t))
	ports := portNum(t, a.Listener.Addr().String()) + "," + portNum(t, b.Listener.Addr().String()) + "," + closed
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "r.db")
	_, errOut, err := captureBoth(t, func() error {
		return run([]string{"run", "-url", a.URL + "/", "-probe", "-ports", ports, "-max-requests", "100", "-db", db, "-ledger", "off", "-json"})
	})
	rep := lastReport(t, errOut)
	if exitCode(err) != exitOK || rep.Stopped != "" || rep.Requests >= 100 {
		t.Fatalf("exit %d, stopped %q after %d requests (budget 100)", exitCode(err), rep.Stopped, rep.Requests)
	}
	if rep.Counts["ports"] != 2 || rep.Resume != "" {
		t.Errorf("ports found %d, want the 2 open ones; resume hint %q", rep.Counts["ports"], rep.Resume)
	}
}
