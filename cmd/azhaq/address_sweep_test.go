package main

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/collectors/pathscol"
	_ "modernc.org/sqlite"
)

// addressLab is one web server on 127.0.0.1 that counts what it is asked.
type addressLab struct {
	port                 string
	root, about, gitHead atomic.Int64
}

func newAddressLab(t *testing.T) *addressLab {
	t.Helper()
	l := &addressLab{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			l.root.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>lab</title><a href="/about">about</a>`)
		case "/about":
			l.about.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>about</title>")
		case "/.git/HEAD":
			l.gitHead.Add(1)
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, l.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	return l
}

// runCIDR maps 127.0.0.1 as an address of a -cidr, the web port named only by
// -web-ports: the address path, no URL given and no port scan.
func (l *addressLab) runCIDR(t *testing.T, db string) report {
	t.Helper()
	_, rep, code := runContract(t, "run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-sources", "none",
		"-web-ports", l.port, "-no-history", "-db", db)
	if code != exitOK {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	return rep
}

// An address of a -cidr that answers HTTP is a web service like a URL given:
// its pages are crawled and its built-in path checks are asked (#328).
func TestRunCIDRAddressThatAnswersIsCrawledAndSwept(t *testing.T) {
	l := newAddressLab(t)
	t.Chdir(t.TempDir())
	rep := l.runCIDR(t, filepath.Join(t.TempDir(), "a.db"))
	if l.about.Load() == 0 {
		t.Errorf("the page the address links to was never crawled")
	}
	if l.gitHead.Load() == 0 {
		t.Errorf("no built-in path check was sent to the address")
	}
	// The URL handed on reads the address's answer: its page is asked once.
	if n := l.root.Load(); n != 1 {
		t.Errorf("the address's page was requested %d times, want 1", n)
	}
	if len(rep.PathChecks) != 1 {
		t.Fatalf("path_checks: %+v", rep.PathChecks)
	}
	if c := rep.PathChecks[0]; c.Sent == nil || *c.Sent == 0 {
		t.Errorf("%s: no sweep on record: %+v", c.Service, c)
	}
}

// resume -retry-failed asks a sweep the run listed and left unrecorded, and
// the failure is gone when the sweep records (#328).
func TestResumeRetryFailedAsksAnUnrecordedSweep(t *testing.T) {
	l := newAddressLab(t)
	t.Chdir(t.TempDir())
	db := filepath.Join(t.TempDir(), "a.db")
	rep := l.runCIDR(t, db)
	service := rep.PathChecks[0].Service
	// The state a run leaves when its sweep did not run and nothing stopped
	// it: no record of the sweep, and the service named for resume.
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DELETE FROM observations WHERE collector = '` + pathscol.Name + `' AND kind = '` + pathscol.SweepKind + `'`,
		`INSERT INTO meta (k, v) VALUES ('` + sweepsKey(rep.RunID) + `', '` + service + `') ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	out, _, _ := cli(t, "query", "-db", db, "-failed", "-json")
	if !strings.Contains(out, service) || !strings.Contains(out, `"retryable":true`) {
		t.Errorf("query -failed does not list the unrecorded sweep as retryable:\n%s", out)
	}

	before := l.gitHead.Load()
	_, errOut, err := captureBoth(t, func() error { return cmdResume([]string{"-db", db, "-retry-failed", "-json"}) })
	rep = lastReport(t, errOut)
	if exitCode(err) != exitOK || !strings.Contains(strings.Join(rep.Notes, "\n"), "-retry-failed: 1 failed targets of run "+rep.RunID+" asked again, 0 still fail") {
		t.Fatalf("the retry: exit %d, notes %q, failed %+v\n%s", exitCode(err), rep.Notes, rep.Failed, errOut)
	}
	if l.gitHead.Load() == before {
		t.Errorf("the sweep was not asked again")
	}
	if len(rep.Failed) != 0 || len(rep.PathChecks) != 1 || rep.PathChecks[0].Sent == nil {
		t.Errorf("failed %+v, path_checks %+v: want the sweep on record and nothing failed", rep.Failed, rep.PathChecks)
	}
}

// The sweeps recorded for resume are the ones the run fails for: none when
// it was stopped (they are left work), none for a sweep that recorded.
func TestUnrecordedSweepsAreTheFailedOnes(t *testing.T) {
	sent := 51
	rep := &report{Command: "run", PathChecks: []pathCheck{
		{Service: "http://a.zz", Listed: 51},
		{Service: "http://b.zz", Listed: 51, Sent: &sent},
		{Service: "http://c.zz", Listed: 51, Reason: "its sweep failed: timeout"},
	}}
	if got := rep.unrecordedSweeps(); len(got) != 1 || got[0] != "http://a.zz" {
		t.Errorf("unrecorded: %v", got)
	}
	rep.Stopped = "interrupted"
	if got := rep.unrecordedSweeps(); len(got) != 0 {
		t.Errorf("a stopped run: %v", got)
	}
}

// -allow HOST:PORT still holds the address's service: the allowed port is
// swept, and the run is complete.
func TestRunCIDRAddressWithAllowedPortIsSwept(t *testing.T) {
	l := newAddressLab(t)
	t.Chdir(t.TempDir())
	_, rep, code := runContract(t, "run", "-cidr", "127.0.0.1/32", "-allow", "127.0.0.1:"+l.port, "-sources", "none",
		"-web-ports", l.port, "-no-history", "-db", filepath.Join(t.TempDir(), "p.db"))
	if code != exitOK || l.gitHead.Load() == 0 {
		t.Fatalf("exit %d, path checks sent %d: failed %+v notes %q", code, l.gitHead.Load(), rep.Failed, rep.Notes)
	}
}
