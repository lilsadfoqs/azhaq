package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// atMost is the ceiling a stage prints, and whether it prints one.
func atMost(st map[string]any) (float64, bool) {
	n, ok := st["at_most"].(float64)
	return n, ok
}

// sentAll is what a stage sent to targets and resolvers.
func sentAll(st map[string]any) float64 {
	return sentIn(st) + stageAmount(st, "actual", "datagrams") + stageAmount(st, "actual", "dns_queries")
}

// The ceiling of a port scan is each port asked on every pass, each open port
// given all its probes, and each UDP port all four of its asks: counted by hand
// on a /28.
func TestPortsCeilingArithmetic(t *testing.T) {
	base := []string{"-cidr", "127.0.0.0/28", "-allow", "127.0.0.0/28", "-sources", "none", "-ledger", "off"}
	for _, c := range []struct {
		name  string
		extra []string
		want  float64
	}{
		{"default", []string{"-ports", "1,2,3"}, 16 * 3 * (2 + 26)},
		{"no detection", []string{"-ports", "1,2,3", "-port-detect", "none"}, 16 * 3 * 2},
		{"no retries", []string{"-ports", "1,2,3", "-port-detect", "none", "-port-retries", "0"}, 16 * 3},
		{"3 retries", []string{"-ports", "1,2,3", "-port-detect", "none", "-port-retries", "3"}, 16 * 3 * 4},
		{"discovery first", []string{"-ports", "1,2,3", "-port-detect", "none", "-port-discover", "first"}, 16 * (3*2 + 4)},
		{"discovery only", []string{"-ports", "1,2,3", "-port-discover", "only"}, 16 * 4},
		{"udp", []string{"-ports", "none", "-ports-udp", "9,10"}, 16 * 2 * 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := planCost(t, append(append([]string{}, base...), c.extra...)...)["ports"]
			if got, ok := atMost(st); !ok || got != c.want {
				t.Errorf("at most %v (%v), want %v: %v", got, ok, c.want, st)
			}
			if st["no_ceiling"] != nil {
				t.Errorf("a bounded scan says no ceiling: %v", st)
			}
		})
	}
}

// A ceiling is never below what the run sent: for each stand-in, a run with a
// port that opens and says nothing, UDP, and a wordlist with directories, and
// each stage that prints a ceiling stays under it. The stages that must print
// one are checked, so the test cannot pass with none.
func TestCeilingHoldsOnStandIns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, open, _ := net.SplitHostPort(ln.Addr().String())
	var hits atomic.Int64
	app := juiceShaped(&hits)
	defer app.Close()
	words := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(words, []byte("a\nb\napi/x\napi/y\nrest/z\nrest/q\nadmin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args []string
		must []string // stages that print a ceiling
	}{
		{"ports with probes", []string{"-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", open + ",1,2", "-ports-udp", "9,10"}, []string{"ports"}},
		{"ports banner", []string{"-cidr", "127.0.0.1/32", "-allow", "127.0.0.1", "-ports", open + ",1", "-port-detect", "banner"}, []string{"ports"}},
		{"dirs", []string{"-url", app.URL + "/", "-allow", "127.0.0.1", "-dirs", words, "-dirs-ext", "php"}, []string{"fuzz"}},
		{"dirs, no calibration", []string{"-url", app.URL + "/", "-allow", "127.0.0.1", "-dirs", words, "-dirs-ac=false"}, []string{"fuzz"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string{}, c.args...), "-sources", "none", "-ledger", "off")
			est := planCost(t, args...)
			sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
			sent := stagesOf(t, sum)
			for _, m := range c.must {
				if _, ok := atMost(est[m]); !ok {
					t.Errorf("%s stage prints no ceiling: %v", m, est[m])
				}
			}
			for stage, st := range est {
				if at, ok := atMost(st); ok && sentAll(sent[stage]) > at {
					t.Errorf("%s stage: the ceiling is %v, the run sent %v", stage, at, sentAll(sent[stage]))
				}
			}
		})
	}
}

// -max-requests is the ceiling of a stage nothing else bounds, and caps one
// that something does; a crawl with no cap says so and names the option.
func TestCeilingFromMaxRequests(t *testing.T) {
	var hits atomic.Int64
	app := juiceShaped(&hits)
	defer app.Close()
	args := []string{"-url", app.URL + "/", "-allow", "127.0.0.1", "-sources", "none"}
	web := planCost(t, args...)["web"]
	if _, ok := atMost(web); ok || web["no_ceiling"] == nil {
		t.Errorf("a crawl with no cap has a ceiling: %v", web)
	}
	out, _, _ := cli(t, append([]string{"plan"}, args...)...)
	if !strings.Contains(out, "no ceiling (-max-requests sets one)") {
		t.Errorf("the plan does not say what bounds the crawl:\n%s", out)
	}
	web = planCost(t, append(args, "-max-requests", "500")...)["web"]
	if at, ok := atMost(web); !ok || at != 500 || web["at_most_by"] != "-max-requests" {
		t.Errorf("web with -max-requests 500: %v", web)
	}
	out, _, _ = cli(t, append(append([]string{"plan"}, args...), "-max-requests", "500")...)
	if !strings.Contains(out, "at most 500 (-max-requests)") {
		t.Errorf("the plan does not print the cap:\n%s", out)
	}
	// A bounded stage under the cap keeps its own bound; over it, the cap.
	ports := []string{"-cidr", "127.0.0.0/28", "-allow", "127.0.0.0/28", "-sources", "none", "-ports", "1,2", "-port-detect", "none"}
	if at, _ := atMost(planCost(t, append(ports, "-max-requests", "1000")...)["ports"]); at != 64 {
		t.Errorf("a cap above the bound changes it: %v", at)
	}
	if at, _ := atMost(planCost(t, append(ports, "-max-requests", "10")...)["ports"]); at != 10 {
		t.Errorf("a cap under the bound is not the ceiling: %v", at)
	}
}

// Targets a domain brings (names, addresses, web services) are not in a ceiling
// counted from the seeds: the stage says so instead of printing one.
func TestCeilingOpenWhenTargetsAreFound(t *testing.T) {
	st := planCost(t, "-domain", "example.test", "-ports", "1,2", "-sources", "none")["ports"]
	if _, ok := atMost(st); ok || !strings.Contains(fmt.Sprint(st["no_ceiling"]), "found under") {
		t.Errorf("a domain's ports have a ceiling: %v", st)
	}
	st = planCost(t, "-cidr", "127.0.0.0/30", "-allow", "127.0.0.0/30", "-allow", "10.0.0.0/8", "-ports", "1", "-sources", "none")["ports"]
	if _, ok := atMost(st); ok || !strings.Contains(fmt.Sprint(st["no_ceiling"]), "-allow") {
		t.Errorf("a scope wider than the targets has a ceiling: %v", st)
	}
	st = planCost(t, "-cidr", "127.0.0.0/30", "-allow", "127.0.0.0/30", "-ports", "1", "-port-all-ips", "-sources", "none")["ports"]
	if _, ok := atMost(st); !ok {
		t.Errorf("-port-all-ips changes nothing for addresses: %v", st)
	}
	st = planCost(t, "-url", "http://127.0.0.1:1/", "-dirs", wordsFile(t, 3), "-dirs-depth", "2", "-allow", "127.0.0.1", "-sources", "none")["fuzz"]
	if _, ok := atMost(st); ok || !strings.Contains(fmt.Sprint(st["no_ceiling"]), "-dirs-depth 2") {
		t.Errorf("-dirs-depth 2 has a ceiling: %v", st)
	}
}

// A lookup is asked again on another resolver when it gets no answer: DNS has
// no ceiling.
func TestCeilingDNSHasNone(t *testing.T) {
	st := planCost(t, "-domain", "example.test", "-dns-brute", wordsFile(t, 5), "-sources", "none")["names"]
	if _, ok := atMost(st); ok || st["no_ceiling"] == nil {
		t.Errorf("DNS queries have a ceiling: %v", st)
	}
}

// -params has an estimate: the first questions of each page the user gave, and
// a run sends at least that.
func TestParamsEstimateIsAFloor(t *testing.T) {
	var hits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>x</title></html>")
	}))
	defer app.Close()
	words := wordsFile(t, 1200)
	args := []string{"-url", app.URL + "/page", "-allow", "127.0.0.1", "-params", words, "-sources", "none", "-ledger", "off", "-no-paths"}
	st := planCost(t, args...)["fuzz"]
	want := float64(3 + (1200+499)/500)
	if got := stageAmount(st, "estimate", "requests"); got != want {
		t.Fatalf("the plan counts %v params requests for one page, want %v: %v", got, want, st)
	}
	sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
	if got := stageAmount(stagesOf(t, sum)["fuzz"], "actual", "requests"); got < want {
		t.Errorf("the floor is %v, the run sent %v", want, got)
	}
}
