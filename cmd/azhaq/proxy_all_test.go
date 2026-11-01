package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/trannghiach/azhaq/internal/egress"
)

// Every command that sends HTTP to a target takes -proxy, and the proxy is
// asked for every request the command sends.
func TestDirsSendsEveryRequestThroughProxy(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 403})
	px, seen := countingProxy(srv, false, 0)
	defer px.Close()
	words := wlist(t, "admin", "nothing", "other")
	out, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-silent", "-proxy", px.URL, "-json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if !strings.Contains(out, "/admin") {
		t.Errorf("the path was not found through the proxy: %s", out)
	}
	got := seen()
	if !slices.Contains(got, "GET /admin") || !slices.Contains(got, "GET /nothing") || !slices.Contains(got, "GET /other") {
		t.Errorf("the proxy saw %v, want every guess", got)
	}
}

func TestDirsFollowsProxyEnvironmentForLoopback(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 403})
	px, seen := countingProxy(srv, false, 0)
	defer px.Close()
	egress.ProxyLoopback = true
	t.Cleanup(func() { egress.ProxyLoopback = false })
	t.Setenv("HTTP_PROXY", px.URL)
	t.Setenv("http_proxy", px.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	words := wlist(t, "admin", "nothing")
	_, errOut, err := captureBoth(t, func() error {
		return cmdDirs([]string{"-u", srv.URL + "/", "-w", words, "-silent"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	if got := seen(); !slices.Contains(got, "GET /admin") {
		t.Errorf("HTTP_PROXY was set and the proxy saw %v", got)
	}
}

func TestFuzzTakesProxyAsX(t *testing.T) {
	srv := dirsServer(t, map[string]int{"/admin": 200})
	px, seen := countingProxy(srv, false, 0)
	defer px.Close()
	words := wlist(t, "admin", "nothing")
	for _, flag := range []string{"-proxy", "-x"} {
		out, errOut, err := captureBoth(t, func() error {
			return cmdFuzz([]string{"-u", srv.URL + "/FUZZ", "-w", words, flag, px.URL, "-s"})
		})
		if err != nil {
			t.Fatalf("%s: %v\n%s", flag, err, errOut)
		}
		if !strings.Contains(out, "admin") {
			t.Errorf("%s: no match: %q", flag, out)
		}
	}
	got := seen()
	if n := strings.Count(strings.Join(got, ","), "GET /nothing"); n != 2 {
		t.Errorf("the proxy saw %v: want every request of both runs", got)
	}
}
