package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trannghiach/azhaq/internal/ledger"
	"github.com/trannghiach/azhaq/internal/neterr"
)

// twoPorts is one host with two services: the page on a links, in markup and
// in its script, to b.
func twoPorts(t *testing.T) (a, b *httptest.Server, bHits *atomic.Int32) {
	t.Helper()
	bHits = new(atomic.Int32)
	b = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits.Add(1)
		fmt.Fprint(w, `<html><title>the other service</title></html>`)
	}))
	t.Cleanup(b.Close)
	a = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><title>app</title><a href="/next">next</a> <a href="%s/admin">other</a><script src="/app.js"></script></html>`, b.URL)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `fetch("%s/api/users"); fetch("/api/me");`, b.URL)
		case "/next", "/api/me":
			fmt.Fprint(w, `<html><title>next</title></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	return a, b, bHits
}

func srvPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	return u.Port()
}

// ledgerMentions counts the ledger's lines that name the port.
func ledgerMentions(t *testing.T, path, port string) int {
	t.Helper()
	n := 0
	if err := ledger.Read(path, func(e ledger.Entry) error {
		if strings.Contains(e.Target, ":"+port) {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// -allow 127.0.0.1:PORT: a crawl of that service does not follow its links,
// its scripts' URLs or anything else to another port of the host; the URLs
// are listed as not requested, with the reason, and nothing is sent.
func TestRunAllowWithAPortStaysOnThePort(t *testing.T) {
	a, b, bHits := twoPorts(t)
	dir := t.TempDir()
	led := filepath.Join(dir, "run.ledger.jsonl")
	_, errOut, code := cli(t, "run", "-url", a.URL+"/", "-allow", "127.0.0.1:"+srvPort(t, a), "-sources", "none",
		"-ledger", led, "-db", filepath.Join(dir, "run.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	if bHits.Load() != 0 || ledgerMentions(t, led, srvPort(t, b)) != 0 {
		t.Fatalf("the other port got %d requests, the ledger names it %d times", bHits.Load(), ledgerMentions(t, led, srvPort(t, b)))
	}
	if rep.Requests == 0 {
		t.Fatalf("the allowed port was not asked: %+v", rep)
	}
	var listed bool
	for _, s := range rep.Skipped {
		if strings.Contains(s.Target, ":"+srvPort(t, b)) && s.Reason == neterr.OutOfPortReason {
			listed = true
		}
	}
	if !listed {
		t.Errorf("no URL of the other port is listed as skipped with the port's reason: %+v", rep.Skipped)
	}
}

// The same flag as an assistant's server passes every command it runs
// (azhaq mcp -allow 127.0.0.1:PORT): a probe of the other port is refused
// before it connects.
func TestProbeAllowWithAPortRefusesAnotherPort(t *testing.T) {
	a, b, bHits := twoPorts(t)
	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(list, []byte(b.URL+"/\n"+a.URL+"/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := cli(t, "probe", "-json", "-silent", "-l", list, "-allow", "127.0.0.1:"+srvPort(t, a))
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %s %+v", code, out, rep)
	}
	if bHits.Load() != 0 {
		t.Fatalf("the other port was probed %d times", bHits.Load())
	}
	var answered, refused bool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		switch row["port"] {
		case srvPort(t, a):
			answered = row["status_code"] == float64(200)
		case srvPort(t, b):
			refused = row["failed"] == true && row["error"] == neterr.OutOfPortReason
		}
	}
	if !answered || !refused {
		t.Errorf("the allowed port answered %v, the other was refused with the port's reason %v: %s", answered, refused, out)
	}
	only := filepath.Join(t.TempDir(), "other.txt")
	_ = os.WriteFile(only, []byte(b.URL+"/\n"), 0o644)
	_, _, code = cli(t, "probe", "-json", "-silent", "-l", only, "-allow", "127.0.0.1:"+srvPort(t, a))
	if code != exitUsage || bHits.Load() != 0 {
		t.Errorf("a list of the other port only: exit %d, %d hits", code, bHits.Load())
	}
}

// A port scan of a host held to one port asks that port only and counts the
// ports it left out.
func TestPortsAllowWithAPortScansThatPortOnly(t *testing.T) {
	var accepted [2]atomic.Int64
	var ports [2]string
	for i := range accepted {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ports[i] = fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
		go func(i int) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted[i].Add(1)
				c.Close()
			}
		}(i)
	}
	// A URL of the allowed port and a range: two code paths.
	for name, target := range map[string][]string{"url": {"-url", "http://127.0.0.1:" + ports[0] + "/"}, "range": {"-cidr", "127.0.0.1/32"}} {
		t.Run(name, func(t *testing.T) {
			before := [2]int64{accepted[0].Load(), accepted[1].Load()}
			dir := t.TempDir()
			led := filepath.Join(dir, "p.ledger.jsonl")
			args := append([]string{"run"}, target...)
			args = append(args, "-allow", "127.0.0.1:"+ports[0], "-ports", ports[0]+","+ports[1], "-port-detect", "none", "-sources", "none",
				"-ledger", led, "-db", filepath.Join(dir, "p.db"), "-json")
			_, errOut, code := cli(t, args...)
			rep := lastReport(t, errOut)
			if code != exitOK && code != exitPartial {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			if accepted[0].Load() == before[0] || accepted[1].Load() != before[1] || ledgerMentions(t, led, ports[1]) != 0 {
				t.Fatalf("connections: allowed %d, other %d, ledger names the other %d times", accepted[0].Load()-before[0], accepted[1].Load()-before[1], ledgerMentions(t, led, ports[1]))
			}
			var noted bool
			for _, n := range rep.Notes {
				noted = noted || strings.Contains(n, "1 ports on 1 addresses were not scanned: -allow lists their hosts with other ports only")
			}
			if !noted {
				t.Errorf("no note counts the port left out: %q", rep.Notes)
			}
		})
	}
}

// The crawl command, with a crawl scope that would follow a link to another
// port of the host, still stays on the port -allow names.
func TestCrawlAllowWithAPortStaysOnThePort(t *testing.T) {
	a, b, bHits := twoPorts(t)
	led := filepath.Join(t.TempDir(), "crawl.ledger.jsonl")
	_, errOut, code := cli(t, "crawl", "-u", a.URL+"/", "-allow", "127.0.0.1:"+srvPort(t, a), "-fs", "fqdn", "-ledger", led, "-json")
	rep := lastReport(t, errOut)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if bHits.Load() != 0 || ledgerMentions(t, led, srvPort(t, b)) != 0 {
		t.Fatalf("the other port got %d requests, the ledger names it %d times", bHits.Load(), ledgerMentions(t, led, srvPort(t, b)))
	}
	var listed bool
	for _, s := range rep.Skipped {
		listed = listed || strings.Contains(s.Target, ":"+srvPort(t, b)) && s.Reason == neterr.OutOfPortReason
	}
	if !listed {
		t.Errorf("no URL of the other port is listed as not requested with the port's reason: %+v %q", rep.Skipped, rep.Notes)
	}
}

// Naming a bare host when -allow lists it with a port says what to do.
func TestRunAllowWithAPortSaysHowToNameTheTarget(t *testing.T) {
	list := filepath.Join(t.TempDir(), "hosts.txt")
	_ = os.WriteFile(list, []byte("127.0.0.1\n"), 0o644)
	_, errOut, code := cli(t, "run", "-list", list, "-allow", "127.0.0.1:9", "-sources", "none", "-db", filepath.Join(t.TempDir(), "x.db"), "-json")
	if code != exitUsage || !strings.Contains(errOut, "an -allow entry lists a host with a port: name the target with it") {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

// A URL on another port of the host is outside the scope: no row of the
// results (crawl text and -json, the run's map), told only in the summary's
// skipped list, and by crawl -do among the links left outside.
func TestUrlsOnAnotherPortAreNotResults(t *testing.T) {
	a, b, bHits := twoPorts(t)
	port := ":" + srvPort(t, b)
	allow := "127.0.0.1:" + srvPort(t, a)
	// A URL as a row names it (a line, or a url, key or endpoint field), not the script text that mentions it.
	row := regexp.MustCompile(`(^|\s|"(url|key|endpoint)":")http://127\.0\.0\.1` + port)
	for _, c := range []struct {
		name string
		args []string
	}{
		{"crawl", []string{"crawl", "-u", a.URL + "/", "-allow", allow}},
		{"crawl -json", []string{"crawl", "-u", a.URL + "/", "-allow", allow, "-json"}},
		{"crawl -jsonl", []string{"crawl", "-u", a.URL + "/", "-allow", allow, "-jsonl"}},
		{"run", []string{"run", "-url", a.URL + "/", "-allow", allow, "-sources", "none", "-db", filepath.Join(t.TempDir(), "r.db")}},
		{"run -json", []string{"run", "-url", a.URL + "/", "-allow", allow, "-sources", "none", "-json", "-db", filepath.Join(t.TempDir(), "rj.db")}},
		{"run -stream -json", []string{"run", "-url", a.URL + "/", "-allow", allow, "-sources", "none", "-stream", "-json", "-db", filepath.Join(t.TempDir(), "rs.db")}},
	} {
		out, errOut, _ := cli(t, c.args...)
		if row.MatchString(out) {
			t.Errorf("%s: a URL of the other port is on stdout:\n%s", c.name, out)
		}
		if !strings.Contains(errOut, port) {
			t.Errorf("%s: the summary does not name the URL left out:\n%s", c.name, errOut)
		}
	}
	out, _, _ := cli(t, "crawl", "-u", a.URL+"/", "-allow", allow, "-do")
	if !strings.Contains(out, port) {
		t.Errorf("-do does not list the link left outside the scope:\n%s", out)
	}
	if bHits.Load() != 0 {
		t.Errorf("the other port got %d requests", bHits.Load())
	}
}
