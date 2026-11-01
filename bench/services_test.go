package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
)

// lab starts a listener that runs fn on each connection; it returns the port.
func lab(t *testing.T, fn func(c net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); fn(c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// What each lab daemon says when it serves (a reply the protocol defines),
// by lab port: a greeting, or the answer to what the check asks.
var serviceSays = map[int]func(c net.Conn){
	16379: asked("+PONG\r\n"),
	13306: says("\x4a\x00\x00\x00\x0a8.0.35\x00"),
	15432: asked("N"),
	17017: quiet,
	11883: asked("\x20\x02\x00\x00"),
	15682: asked("\x01\x00\x00\x00\x00\x01\x00\x0a\x00\x0a"),
	21211: asked("VERSION 1.6.21\r\n"),
	12222: says("SSH-2.0-OpenSSH_9.6\r\n"),
	10021: says("220 ftp ready\r\n"),
	10025: says("220 mailpit ESMTP\r\n"),
	18825: asked("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	10389: asked("\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"),
	10445: quiet,
	19200: asked("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
	10053: dnsTCP,
}

// dnsTCP is a DNS server over TCP that frames as the protocol does: it
// reads the 2-byte length and then exactly that many bytes (a query that
// is not that long gets no answer), and refuses the name, as a server
// does for a zone it does not hold.
func dnsTCP(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return
	}
	body := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := io.ReadFull(c, body); err != nil {
		return
	}
	var q dns.Msg
	if q.Unpack(body) != nil {
		return
	}
	r := new(dns.Msg)
	r.SetRcode(&q, dns.RcodeRefused)
	wire, _ := r.Pack()
	// Written in two pieces, as a server may: the probe reads on.
	c.Write([]byte{byte(len(wire) >> 8), byte(len(wire))})
	time.Sleep(50 * time.Millisecond)
	c.Write(wire)
}

func says(s string) func(net.Conn) {
	return func(c net.Conn) { c.Write([]byte(s)); time.Sleep(time.Second) }
}
func asked(s string) func(net.Conn) {
	return func(c net.Conn) {
		if n, _ := c.Read(make([]byte, 64)); n > 0 {
			c.Write([]byte(s))
		}
		time.Sleep(time.Second)
	}
}
func quiet(c net.Conn) { time.Sleep(time.Second) }

// A daemon that is up is serving; docker's proxy, which accepts and closes
// while the container starts, is not, for any of the lab's protocols.
func TestServingNeedsTheDaemonNotTheProxy(t *testing.T) {
	proxy := lab(t, func(c net.Conn) {})
	for _, s := range serviceTruth {
		r, ok := readyBy[s.port]
		if !ok {
			t.Errorf("%d %s has no readiness check", s.port, s.what)
			continue
		}
		says, ok := serviceSays[s.port]
		if !ok {
			t.Fatalf("%d %s: the test has no reply for it", s.port, s.what)
		}
		if !servingAs(lab(t, says), r) {
			t.Errorf("%d %s: a daemon that answers is not taken as serving", s.port, s.what)
		}
		if servingAs(proxy, r) {
			t.Errorf("%d %s: a connection that is accepted and closed is taken as serving", s.port, s.what)
		}
	}
	// A daemon that answers with the wrong thing, or Elasticsearch still starting.
	if servingAs(lab(t, asked("HTTP/1.1 503 Service Unavailable\r\n\r\n")), readyBy[19200]) {
		t.Error("Elasticsearch answering 503 is taken as serving")
	}
	if servingAs(lab(t, says("HELO\r\n")), readyBy[12222]) {
		t.Error("something that is not an SSH greeting is taken as serving")
	}
}

// The wait ends when the last daemon serves, and names what never did.
func TestWaitServingWaitsForTheDaemons(t *testing.T) {
	started := time.Now().Add(300 * time.Millisecond)
	late := lab(t, func(c net.Conn) {
		if time.Now().Before(started) {
			return // the proxy, before the daemon is up
		}
		c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		time.Sleep(time.Second)
	})
	never := lab(t, func(c net.Conn) {})
	old := readyBy
	defer func() { readyBy = old }()
	readyBy = map[int]serviceReady{late: old[12222], never: old[12222]}
	t0 := time.Now()
	not := waitServing(time.Second, 20*time.Millisecond, []int{late, never})
	if len(not) != 1 || not[0] != never {
		t.Fatalf("not serving: %v, want [%d]", not, never)
	}
	if d := time.Since(t0); d < time.Second {
		t.Errorf("gave up after %v, before the wait was over", d)
	}
	t0 = time.Now()
	if not := waitServing(5*time.Second, 20*time.Millisecond, []int{late}); len(not) != 0 || time.Since(t0) > time.Second {
		t.Errorf("a daemon that serves is waited for %v: %v", time.Since(t0), not)
	}
}

// A daemon that never served leaves its container's last log lines in the
// check, also when the container exited and docker ps shows no port for it.
func TestDaemonLogsNameTheContainer(t *testing.T) {
	old := docker
	defer func() { docker = old }()
	docker = func(args ...string) (string, error) {
		switch args[0] {
		case "ps":
			return "azq-svc-ftp|Exited (1) 3 minutes ago|\nazq-svc-mail|Up 4 minutes|127.0.0.1:10025->1025/tcp", nil
		case "logs":
			return "vsftpd: bind failed\nexiting", nil
		}
		return "", nil
	}
	got := daemonLogs([]int{10021})
	for _, want := range []string{"10021 azq-svc-ftp (Exited (1) 3 minutes ago)", "vsftpd: bind failed ; exiting", "azq-svc-mail Up 4 minutes"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
	docker = func(...string) (string, error) { return "", fmt.Errorf("no docker") }
	if got := daemonLogs([]int{10021}); !strings.Contains(got, "no docker") {
		t.Errorf("without docker: %q", got)
	}
}

// delfer/alpine-ftp-server builds a user's home with adduser, which fails
// when the home's parent does not exist: the image no longer creates /ftp,
// so the lab names a folder under /home (the image's README form
// name|password|folder).
func TestFTPLabUserHasAHomeThatExists(t *testing.T) {
	raw, err := os.ReadFile("services.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	users := cfg.Services["ftp"].Environment["USERS"]
	f := strings.Split(users, "|")
	if len(f) < 3 || !strings.HasPrefix(f[2], "/home/") {
		t.Errorf("USERS %q: the third field must be a folder under /home", users)
	}
}

// The ftp lab's container must live as long as vsftpd does. The image's own
// start backgrounds the daemon and lets pidproxy watch a pid taken with
// `pgrep vsftpd | tail -n 1`, which can be a process that is gone two
// seconds later: the container then exits 0 and the port never serves. The
// lab runs vsftpd itself in the foreground; vsftpd reads its options in
// order, so -obackground=NO must come after the config file that says YES.
func TestFTPLabRunsVsftpdInTheForeground(t *testing.T) {
	raw, err := os.ReadFile("services.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Services map[string]struct {
			Command []string `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cmd := cfg.Services["ftp"].Command
	if len(cmd) == 0 || cmd[0] != "vsftpd" {
		t.Fatalf("ftp command %q: want vsftpd run by the lab, not the image's pidproxy start", cmd)
	}
	conf, bg := -1, -1
	for i, a := range cmd {
		switch {
		case !strings.HasPrefix(a, "-"):
			if i > 0 {
				conf = i
			}
		case a == "-obackground=NO":
			bg = i
		}
	}
	if conf < 0 || bg < conf {
		t.Errorf("ftp command %q: -obackground=NO must follow the config file (index %d, option at %d)", cmd, conf, bg)
	}
}
