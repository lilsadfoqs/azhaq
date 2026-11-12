package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// udpPorts binds an answering UDP port and n silent ones on 127.0.0.1.
func udpPorts(t *testing.T, n int) (answers int, silent []int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			k, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:k], from)
		}
	}()
	for i := 0; i < n; i++ {
		s, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { s.Close() })
		go func() {
			buf := make([]byte, 512)
			for {
				if _, _, err := s.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		silent = append(silent, s.LocalAddr().(*net.UDPAddr).Port)
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, silent
}

// run's map lists a UDP port that answered and counts the silent ones of an
// address in one line, as ports does; -all-rows lists each and -json marks
// each row's fold.
func TestRunFoldsSilentUDPPorts(t *testing.T) {
	answers, silent := udpPorts(t, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><title>x</title></html>")
	}))
	t.Cleanup(srv.Close)
	pu := fmt.Sprintf("%d,%d,%d,%d", answers, silent[0], silent[1], silent[2])
	args := func(extra ...string) []string {
		return append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none",
			"-ports", "none", "-ports-udp", pu, "-port-detect", "none", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
	}
	text := func(extra ...string) string {
		out, errOut, err := captureBoth(t, func() error { return cmdRun(args(extra...)) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return out
	}
	out := text()
	if !strings.Contains(out, fmt.Sprintf("Port 127.0.0.1:%d/udp", answers)) {
		t.Errorf("the port that answered is not a row:\n%s", out)
	}
	for _, p := range silent {
		if strings.Contains(out, fmt.Sprintf("127.0.0.1:%d/udp  ", p)) {
			t.Errorf("silent port %d is a row of its own:\n%s", p, out)
		}
	}
	if want := "folded silent-udp: 3 UDP ports of 127.0.0.1 answered no datagram"; !strings.Contains(out, want) {
		t.Errorf("no %q:\n%s", want, out)
	}
	all := text("-all-rows")
	if strings.Contains(all, "folded silent-udp") {
		t.Errorf("-all-rows folds:\n%s", all)
	}
	for _, p := range silent {
		if !strings.Contains(all, fmt.Sprintf("127.0.0.1:%d/udp", p)) {
			t.Errorf("-all-rows lacks silent port %d:\n%s", p, all)
		}
	}
	marked, ports := 0, 0
	for _, l := range lines(text("-json")) {
		var row map[string]any
		if json.Unmarshal([]byte(l), &row) != nil || row["type"] != "Port" {
			continue
		}
		ports++
		if row["fold"] == "silent-udp" {
			marked++
		}
	}
	if ports != 4 || marked != 3 {
		t.Errorf("-json has %d port rows, %d marked silent-udp, want 4 and 3", ports, marked)
	}
}

// Images, fonts and media a page only references are counted in one line of
// their class and never asked, whatever the file is called (an extension the
// crawler does not know, an image endpoint); -all-rows lists each.
func TestRunFoldsAssetsPagesOnlyReference(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>app</title><link rel="stylesheet" href="/site.css"></head><body>
<img src="/img/a.png"><img src="/img/photo.jfif"><img srcset="/_next/image?url=%2Fa&w=640 1x, /_next/image?url=%2Fa&w=1080 2x" src="/_next/image?url=%2Fa&w=1920">
<video poster="/m/p.tiff"><source src="/m/clip.mov"></video><audio src="/m/song.m4a"></audio><a href="/about">about</a></body></html>`)
		case "/site.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `@font-face { src: url('/fonts/f.woff2') } b { background: url(/img/bg.jfif) }`)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>about</title></html>`)
		default:
			w.Header().Set("Content-Type", "image/jpeg")
			fmt.Fprint(w, "x")
		}
	}))
	t.Cleanup(srv.Close)
	assets := []string{"/img/a.png", "/img/photo.jfif", "/_next/image", "/m/p.tiff", "/m/clip.mov", "/m/song.m4a", "/fonts/f.woff2", "/img/bg.jfif"}
	text := func(extra ...string) string {
		args := append([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none", "-ports", "none",
			"-db", filepath.Join(t.TempDir(), "w.db")}, extra...)
		out, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		return out
	}
	out := text()
	for _, p := range assets {
		if strings.Contains(out, "URL "+srv.URL+p) {
			t.Errorf("the default view lists %s:\n%s", p, out)
		}
	}
	for _, want := range []string{"URL " + srv.URL + "/about ", "folded beyond-depth: 10 assets"} {
		if !strings.Contains(out, want) {
			t.Errorf("the default view lacks %q:\n%s", want, out)
		}
	}
	mu.Lock()
	for _, p := range assets {
		if asked[p] != 0 {
			t.Errorf("%s was asked %d times: a page only references it", p, asked[p])
		}
	}
	mu.Unlock()
	all := text("-all-rows")
	if strings.Contains(all, "folded beyond-depth") {
		t.Errorf("-all-rows folds:\n%s", all)
	}
	for _, p := range assets {
		if !strings.Contains(all, "URL "+srv.URL+p) {
			t.Errorf("-all-rows lacks %s:\n%s", p, all)
		}
	}
}

// stamped runs fn with stdout read line by line, and says when each line came
// and when fn returned.
func stamped(t *testing.T, fn func() error) (at []time.Time, text []string, end time.Time, err error) {
	t.Helper()
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			at, text = append(at, time.Now()), append(text, sc.Text())
		}
	}()
	err = fn()
	end = time.Now()
	_ = w.Close()
	os.Stdout = old
	<-done
	return at, text, end, err
}

// ports over a range prints an open port as it is found, not when the scan
// ends. 127.0.0.0/29 is asked a common port (asked first, so each address's
// scan finds it at once) and 300 others at a rate that keeps the scan over a second.
func TestPortsRangePrintsAnOpenPortBeforeTheScanEnds(t *testing.T) {
	t.Chdir(t.TempDir())
	var port int
	var ls []net.Listener
	// In nmap's top 100, which a scan asks before the other ports.
	for _, p := range []int{49152, 49153, 49154, 49155, 49156, 49157, 9999, 7070, 8009, 8008, 3128, 5666, 5631, 4899} {
		ls = ls[:0]
		for i := 1; i <= 3; i++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.%d:%d", i, p))
			if err != nil {
				break
			}
			ls = append(ls, l)
		}
		if len(ls) == 3 {
			port = p
			break
		}
		for _, l := range ls {
			l.Close()
		}
	}
	if port == 0 {
		t.Skip("no common port is free on 127.0.0.1-3")
	}
	for _, l := range ls {
		l := l
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	spec := fmt.Sprintf("%d,50001-50300", port)
	at, text, end, err := stamped(t, func() error {
		return run([]string{"ports", "-host", "127.0.0.0/29", "-p", spec, "-rate", "1000", "-connect-timeout", "200ms", "-detect", "none", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(text) != 3 {
		t.Fatalf("%d rows, want the 3 open ports: %q", len(text), text)
	}
	if lead := end.Sub(at[0]); lead < 800*time.Millisecond {
		t.Errorf("the first row came %v before the scan ended, want it as the port was found (rows %q)", lead, text)
	}
}
