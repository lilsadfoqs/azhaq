package contract

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The controls a user sets hold for what the binary sends: the kill file
// stops it, a denied host is not asked, and the ledger is where the user
// puts it.

var killStopped = regexp.MustCompile(`^the kill switch: kill file (\S+) exists, \d+ tasks known and not done \(remove it, then azhaq resume\)$`)

// The default kill file is DB.stop beside the workspace, -kill-file names
// another in its place, a drop-in command without -db has none, and
// removing the file lets azhaq resume go on.
func TestTheKillFileStopsTheRunAndResumeGoesOn(t *testing.T) {
	site := func(l *Labs, extra ...string) []string {
		return append([]string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none"}, extra...)
	}
	t.Run("default", func(t *testing.T) {
		l := newLabs(t)
		stop := filepath.Join(l.Dir, "w.db.stop")
		must(t, os.WriteFile(stop, nil, 0o644))
		r := RunRaw(t, l.Dir, nil, append(site(l, "-db", "w.db"), "-json")...)
		if m := killStopped.FindStringSubmatch(r.Summary.Stopped); r.Code != 4 || m == nil || m[1] != "w.db.stop" {
			t.Errorf("exit %d, stopped %q", r.Code, r.Summary.Stopped)
		}
		if n := l.Site.Wire.Total(); n != 0 {
			t.Errorf("%d requests reached the site with the kill file in place", n)
		}
		must(t, os.Remove(stop))
		r = RunRaw(t, l.Dir, nil, "resume", "-db", "w.db", "-json")
		if r.Code != 0 || r.Summary.Requests == 0 {
			t.Errorf("resume after removing the file: exit %d, %d requests\n%s", r.Code, r.Summary.Requests, r.Stderr)
		}
	})
	t.Run("-kill-file names another in its place", func(t *testing.T) {
		l := newLabs(t)
		must(t, os.WriteFile(filepath.Join(l.Dir, "w.db.stop"), nil, 0o644))
		r := RunRaw(t, l.Dir, nil, append(site(l, "-db", "w.db", "-kill-file", "other.stop"), "-json")...)
		if r.Code != 0 || l.Site.Wire.Total() == 0 {
			t.Errorf("the default file stopped a run that named another: exit %d, %d requests", r.Code, l.Site.Wire.Total())
		}
		must(t, os.WriteFile(filepath.Join(l.Dir, "other.stop"), nil, 0o644))
		l.Site.Wire.Reset()
		r = RunRaw(t, l.Dir, nil, append(site(l, "-db", "x.db", "-kill-file", "other.stop"), "-json")...)
		if m := killStopped.FindStringSubmatch(r.Summary.Stopped); r.Code != 4 || m == nil || m[1] != "other.stop" || l.Site.Wire.Total() != 0 {
			t.Errorf("exit %d, stopped %q, %d requests", r.Code, r.Summary.Stopped, l.Site.Wire.Total())
		}
	})
	t.Run("a drop-in command without -db has none", func(t *testing.T) {
		l := newLabs(t)
		for _, name := range []string{"DB.stop", "probe.stop", ".stop", "stop"} {
			must(t, os.WriteFile(filepath.Join(l.Dir, name), nil, 0o644))
		}
		r := RunRaw(t, l.Dir, nil, "probe", "-u", l.Site.URL, "-json")
		if r.Code != 0 || l.Site.Wire.Total() == 0 {
			t.Errorf("a file beside a command with no workspace stopped it: exit %d, %d requests", r.Code, l.Site.Wire.Total())
		}
	})
}

// The ledger is DB.ledger.jsonl beside the workspace; -ledger FILE puts it
// elsewhere and -ledger off writes none; a drop-in command without -db
// writes one only with -ledger FILE.
func TestTheLedgerIsWhereTheUserPutsIt(t *testing.T) {
	exists := func(l *Labs, name string) bool { _, err := os.Stat(filepath.Join(l.Dir, name)); return err == nil }
	run := func(l *Labs, extra ...string) {
		RunRaw(t, l.Dir, nil, append([]string{"run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-json"}, extra...)...)
	}
	l := newLabs(t)
	run(l, "-db", "w.db")
	if !exists(l, "w.db.ledger.jsonl") {
		t.Error("a run with a workspace has no ledger beside it")
	}
	l = newLabs(t)
	run(l, "-db", "w.db", "-ledger", "elsewhere.jsonl")
	if !exists(l, "elsewhere.jsonl") || exists(l, "w.db.ledger.jsonl") {
		t.Error("-ledger FILE did not put the ledger there and only there")
	}
	l = newLabs(t)
	run(l, "-db", "w.db", "-ledger", "off")
	if m, _ := filepath.Glob(filepath.Join(l.Dir, "*ledger*")); len(m) != 0 {
		t.Errorf("-ledger off wrote %v", m)
	}
	l = newLabs(t)
	RunRaw(t, l.Dir, nil, "probe", "-u", l.Site.URL, "-json")
	if m, _ := filepath.Glob(filepath.Join(l.Dir, "*ledger*")); len(m) != 0 {
		t.Errorf("a drop-in command without -db wrote %v", m)
	}
	RunRaw(t, l.Dir, nil, "probe", "-u", l.Site.URL, "-ledger", "l.jsonl", "-json")
	if !exists(l, "l.jsonl") {
		t.Error("a drop-in command with -ledger FILE wrote none")
	}
}

// The ledger records what is sent about a target, to a third party and to a
// resolver: not the user's own endpoints, which are a -replay-proxy, the
// link of a worker to its run and where -seal-to posts the seal.
func TestTheLedgerHoldsNoEndpointOfTheUser(t *testing.T) {
	notIn := func(t *testing.T, ledger string, hosts ...string) {
		t.Helper()
		lines := readLedger(t, ledger)
		if len(lines) < 2 {
			t.Fatalf("%s holds %d lines", ledger, len(lines))
		}
		for _, line := range lines {
			for _, h := range hosts {
				if line.Host == h || strings.Contains(line.Target, h) {
					t.Errorf("the ledger lists the user's own endpoint %s: %+v", h, line)
				}
			}
		}
	}
	t.Run("-replay-proxy", func(t *testing.T) {
		l := newLabs(t)
		w := l.File("w.txt", "about\nproducts\nnope\n")
		RunRaw(t, l.Dir, nil, "fuzz", "-u", l.Site.URL+"/FUZZ", "-w", w, "-replay-proxy", l.Proxy.URL, "-ledger", "l.jsonl", "-json")
		if l.Proxy.Wire.Total() == 0 {
			t.Fatal("the proxy was sent no match: the lab asks nothing")
		}
		notIn(t, filepath.Join(l.Dir, "l.jsonl"), strings.TrimPrefix(l.Proxy.URL, "http://"))
	})
	t.Run("-seal-to", func(t *testing.T) {
		l := newLabs(t)
		got := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, 4096)
			n, _ := r.Body.Read(b)
			got <- string(b[:n])
		}))
		t.Cleanup(srv.Close)
		RunRaw(t, l.Dir, nil, "run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db", "-seal-to", srv.URL, "-json")
		select {
		case body := <-got:
			if !strings.Contains(body, `"seal"`) {
				t.Errorf("the URL got %q, not the seal", body)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the seal was not posted")
		}
		notIn(t, filepath.Join(l.Dir, "w.db.ledger.jsonl"), strings.TrimPrefix(srv.URL, "http://"))
	})
	t.Run("a worker's link to its run", func(t *testing.T) {
		l := newLabs(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		must(t, err)
		addr := ln.Addr().String()
		ln.Close()
		env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + l.Dir, "AZHAQ_DATA_DIR=" + filepath.Join(l.Dir, "data")}
		srv := exec.Command(binPath, "run", "-url", l.Site.URL, "-allow", l.Allow(), "-sources", "none", "-db", "w.db",
			"-serve", addr, "-worker-token", "tok", "-parallel", "1", "-quiet", "-json")
		srv.Dir, srv.Env = l.Dir, env
		must(t, srv.Start())
		for i := 0; ; i++ {
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				break
			} else if i > 200 {
				_ = srv.Process.Kill()
				t.Fatalf("the run did not listen: %v", err)
			}
			time.Sleep(25 * time.Millisecond)
		}
		wrk := exec.Command(binPath, "worker", "-server", addr, "-token", "tok", "-slots", "4")
		wrk.Dir, wrk.Env = l.Dir, env
		must(t, wrk.Start())
		done := make(chan error, 1)
		go func() { done <- srv.Wait() }()
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			_ = srv.Process.Kill()
			t.Fatal("the run did not end")
		}
		_ = wrk.Process.Kill()
		_ = wrk.Wait()
		notIn(t, filepath.Join(l.Dir, "w.db.ledger.jsonl"), addr)
	})
}

// A denied host is not asked, even named as a target, and a port in -deny is
// dropped: the host is kept out on every port.
func TestADeniedHostIsNotAskedEvenAsATarget(t *testing.T) {
	for _, c := range []struct {
		name string
		deny func(l *Labs) string
	}{
		{"-deny HOST", func(l *Labs) string { return "127.0.0.1" }},
		{"-deny HOST:OTHERPORT", func(l *Labs) string { return "127.0.0.1:1" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLabs(t)
			for _, args := range [][]string{
				{"run", "-url", l.Site.URL, "-allow", "127.0.0.1", "-deny", c.deny(l), "-sources", "none", "-db", "w.db"},
				{"crawl", "-u", l.Site.URL, "-d", "2", "-allow", "127.0.0.1", "-deny", c.deny(l)},
				{"probe", "-u", l.Site.URL, "-allow", "127.0.0.1", "-deny", c.deny(l)},
			} {
				r := RunRaw(t, l.Dir, nil, append(args, "-json")...)
				if n := l.Site.Wire.Total(); n != 0 {
					t.Errorf("%s: %d requests reached a denied host", args[0], n)
				}
				if r.Code == 0 {
					t.Errorf("%s: exit 0 though its only target is denied", args[0])
				}
			}
		})
	}
}
