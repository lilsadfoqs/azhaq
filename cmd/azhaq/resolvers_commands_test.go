package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Every command that takes -resolvers asks them for the target's name and
// never the system's resolver, whichever way it sets up its transport.
func TestResolversAnswerEveryNameInEveryCommand(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><title>home</title><a href="/a?id=1">a</a></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	host := "app.lab.test" // no system resolver knows it
	site := "http://" + host + ":" + port
	for _, c := range []struct {
		name string
		args func(led string) []string
	}{
		{"fuzz", func(led string) []string {
			return []string{"fuzz", "-u", site + "/?id=FUZZ", "-w", wlist(t, "x"), "-mc", "all", "-allow", host, "-ledger", led, "-json"}
		}},
		{"dirs", func(led string) []string {
			return []string{"dirs", "-u", site + "/FUZZ", "-w", wlist(t, "a"), "-allow", host, "-ledger", led, "-json"}
		}},
		{"run -dirs", func(led string) []string {
			return []string{"run", "-url", site + "/", "-dirs", wlist(t, "a"), "-sources", "none", "-allow", host, "-ledger", led, "-db", filepath.Join(t.TempDir(), "r.db"), "-json"}
		}},
		{"probe", func(led string) []string {
			return []string{"probe", "-u", site + "/", "-allow", host, "-ledger", led, "-json"}
		}},
		{"crawl", func(led string) []string {
			return []string{"crawl", "-u", site + "/", "-allow", host, "-ledger", led, "-json"}
		}},
		{"params", func(led string) []string {
			return []string{"params", "-u", site + "/", "-allow", host, "-ledger", led, "-json"}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			served.Store(0)
			var asked atomic.Int64
			zone := serveCountingZone(t, &asked, map[string]string{host: "127.0.0.1"})
			led := filepath.Join(t.TempDir(), "run.ledger.jsonl")
			args := c.args(led)
			args = append(args[:1:1], append([]string{"-resolvers", zone}, args[1:]...)...)
			if c.name == "run -dirs" {
				args = append([]string{"run", "-resolvers", zone}, args[3:]...)
			}
			_, errOut, _ := cli(t, args...)
			if served.Load() == 0 || asked.Load() == 0 {
				t.Fatalf("the target was asked %d times, the resolver %d: the name was not resolved at -resolvers\n%s", served.Load(), asked.Load(), errOut)
			}
			system, toZone := dnsLines(t, led, zone)
			if system != 0 || toZone == 0 {
				t.Errorf("the ledger lists %d dns lines to the system's resolver and %d to -resolvers", system, toZone)
			}
		})
	}
}

// A named resolver that does not answer is the end of the name: the system's
// resolver is not asked in its place, and no failure names it.
func TestDeadResolversDoNotFallBackToTheSystem(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Add(1) }))
	defer srv.Close()
	site := "http://app.lab.test:" + srvPort(t, srv)
	for _, args := range [][]string{
		{"fuzz", "-u", site + "/FUZZ", "-w", wlist(t, "x"), "-mc", "all", "-allow", "app.lab.test", "-json"},
		{"dirs", "-u", site + "/FUZZ", "-w", wlist(t, "x"), "-allow", "app.lab.test", "-json"},
		{"probe", "-u", site + "/", "-allow", "app.lab.test", "-json"},
	} {
		t.Run(args[0], func(t *testing.T) {
			served.Store(0)
			_, errOut, _ := cli(t, append([]string{args[0], "-resolvers", "127.0.0.1:1"}, args[1:]...)...)
			if n := served.Load(); n != 0 {
				t.Errorf("%d requests reached the target round the named resolver", n)
			}
			if strings.Contains(errOut, "lookup app.lab.test on") {
				t.Errorf("the system's resolver was asked for the name:\n%s", strings.TrimSpace(errOut))
			}
		})
	}
}
