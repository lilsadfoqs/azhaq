package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// bannerPort is an open port that greets with banner, as an FTP or SSH
// server does.
func bannerPort(t *testing.T, banner string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_, _ = c.Write([]byte(banner))
				_, _ = c.Read(make([]byte, 4096))
			}()
		}
	}()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}

// run -ports on open ports that are not web services (FTP, SSH) is a
// complete run: each is a Port row and a note, never a failed target, and
// the HTTP stage asks each of them once, not once per scheme. The web port
// beside them is still found and mapped.
func TestRunPortsNonHTTPServicesAreNotFailures(t *testing.T) {
	ftp := bannerPort(t, "220 FTP ready\r\n")
	ssh := bannerPort(t, "SSH-2.0-OpenSSH_9.0\r\n")
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>app</title></html>")
	}))
	defer web.Close()
	_, webPort, _ := net.SplitHostPort(web.Listener.Addr().String())
	shut, _ := net.Listen("tcp", "127.0.0.1:0")
	shutPort := fmt.Sprint(shut.Addr().(*net.TCPAddr).Port)
	shut.Close()

	dir := t.TempDir()
	led := filepath.Join(dir, "r.ledger.jsonl")
	out, errOut, code := cli(t, "run", "-list", hostsFile(t, "127.0.0.1"), "-ports", strings.Join([]string{ftp, ssh, webPort, shutPort}, ","),
		"-port-detect", "none", "-port-retries", "0", "-allow", "127.0.0.1", "-no-paths", "-depth", "0", "-sources", "none",
		"-ledger", led, "-db", filepath.Join(dir, "r.db"), "-json")
	rep := lastReport(t, errOut)
	if code != exitOK || len(rep.Failed) != 0 || !rep.Complete {
		t.Fatalf("exit %d, failed %+v, complete %v, notes %q", code, rep.Failed, rep.Complete, rep.Notes)
	}
	ports := map[string]bool{}
	for _, r := range jsonRows(t, out) {
		if r["type"] == "Port" {
			ports[fmt.Sprint(r["key"])] = true
		}
		if key := fmt.Sprint(r["key"]); strings.Contains(key, ":"+ftp+"/") || strings.Contains(key, ":"+ssh+"/") {
			if r["type"] != "Port" {
				t.Errorf("a non-web port has a URL row: %v", r)
			}
		}
	}
	for _, p := range []string{ftp, ssh, webPort} {
		if !ports["127.0.0.1:"+p+"/tcp"] {
			t.Errorf("no Port row for %s in %v", p, ports)
		}
	}
	if ports["127.0.0.1:"+shutPort+"/tcp"] {
		t.Errorf("the closed port has a row")
	}
	notes := strings.Join(rep.Notes, "\n")
	for _, p := range []string{ftp, ssh} {
		if !strings.Contains(notes, "not a web service") || !strings.Contains(notes, "127.0.0.1:"+p) {
			t.Errorf("notes lack the non-web port %s: %q", p, rep.Notes)
		}
	}
	if strings.Contains(notes, webPort+",") || strings.Contains(notes, "127.0.0.1:"+webPort+" ") {
		t.Errorf("the web port is named a non-web service: %q", rep.Notes)
	}
	asked := map[string]int{}
	_ = ledger.Read(led, func(e ledger.Entry) error {
		if e.IsTarget() && e.Kind == "http" {
			asked[e.Target]++
		}
		return nil
	})
	for _, p := range []string{ftp, ssh} {
		if n := asked["http://127.0.0.1:"+p+"/"]; n != 1 {
			t.Errorf("port %s asked %d times over HTTP, want 1", p, n)
		}
		if n := asked["https://127.0.0.1:"+p+"/"]; n != 0 {
			t.Errorf("port %s asked %d times over TLS, want 0", p, n)
		}
	}
	if n := asked["http://127.0.0.1:"+webPort+"/"]; n != 1 {
		t.Errorf("the web port was asked %d times over HTTP, want 1", n)
	}
	if n := asked["https://127.0.0.1:"+webPort+"/"]; n != 0 {
		t.Errorf("the plain web port was asked over TLS %d times", n)
	}
	// 4 connects, 443 and 80 of the bare address, the page, its favicon, 2 banners.
	if want := int64(4 + 2 + 2 + 2); rep.Requests != want {
		t.Errorf("%d requests, want %d", rep.Requests, want)
	}
}
