package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// planCost is the estimate of a plan, by stage.
func planCost(t *testing.T, args ...string) map[string]map[string]any {
	t.Helper()
	out, _, _ := cli(t, append(append([]string{"plan"}, args...), "-json")...)
	var p struct {
		Estimate struct {
			Stages []map[string]any `json:"stages"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	byStage := map[string]map[string]any{}
	for _, st := range p.Estimate.Stages {
		byStage[st["stage"].(string)] = st
	}
	return byStage
}

// estimated is what a plan counted for a stage, requests and connects.
func estimated(st map[string]any) float64 {
	return stageAmount(st, "estimate", "requests") + stageAmount(st, "estimate", "connects") + stageAmount(st, "estimate", "datagrams") + stageAmount(st, "estimate", "dns_queries")
}

// loopbackPort is a TCP listener on 127.0.0.3 and the port it holds.
func loopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.3:0")
	if err != nil {
		t.Skipf("no 127.0.0.3: %v", err)
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
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

// The estimate of a port scan counts each address of a range the scope
// allows, as the run asks them: on a /28 of loopback it is the connects the
// run makes, for every size of port list, with -deny, with a port of an
// address of its own, and with the ports a rule keeps out.
func TestPortsEstimateCountsEveryAddressOfARange(t *testing.T) {
	open := loopbackPort(t)
	base := []string{"-cidr", "127.0.0.0/28", "-sources", "none", "-port-detect", "none", "-ledger", "off"}
	for _, c := range []struct {
		name  string
		extra []string
		want  float64 // connects, by hand
	}{
		{"one port", []string{"-ports", open, "-allow", "127.0.0.0/28"}, 16},
		{"a list", []string{"-ports", open + ",1,2,3,4-9", "-allow", "127.0.0.0/28"}, 16 * 10},
		{"-deny", []string{"-ports", open + ",1,2", "-allow", "127.0.0.0/28", "-deny", "127.0.0.8/29", "-deny", "127.0.0.1"}, 7 * 3},
		{"a smaller -allow", []string{"-ports", open + ",1", "-allow", "127.0.0.0/30"}, 4 * 2},
		{"-ports-on", []string{"-ports", open + ",1,2", "-ports-on", "127.0.0.4=" + open, "-allow", "127.0.0.0/28"}, 15*3 + 1},
		{"a port the rule keeps out", []string{"-ports", open + ",1", "-allow", "127.0.0.0/29", "-allow", "127.0.0.9:" + open}, 8*2 + 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string{}, base...), c.extra...)
			est := planCost(t, args...)["ports"]
			if est == nil {
				t.Fatalf("the plan has no ports stage")
			}
			if got := stageAmount(est, "estimate", "connects"); got != c.want {
				t.Errorf("the plan estimates %v connects, want %v", got, c.want)
			}
			sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
			sent := stagesOf(t, sum)["ports"]
			if sent == nil {
				t.Fatalf("the run has no ports stage: %v", sum["cost"])
			}
			if got := stageAmount(sent, "actual", "connects"); got != c.want {
				t.Errorf("the run made %v connects, want %v (the plan said %v)", got, c.want, stageAmount(est, "estimate", "connects"))
			}
		})
	}
}

// A floor is not above what the run sent: -port-discover first asks the ports
// of the addresses that answer, which the plan does not know, and UDP is sent
// to addresses that are not a CDN's only.
func TestPortsFloorOfADiscoveredRangeAndOfUDP(t *testing.T) {
	open := loopbackPort(t)
	args := []string{"-cidr", "127.0.0.0/28", "-allow", "127.0.0.0/28", "-sources", "none", "-port-detect", "none", "-ledger", "off"}
	for _, c := range []struct {
		name  string
		extra []string
		want  float64
		what  string // the amount counted: connects (TCP) or datagrams (UDP)
	}{
		{"discover first", []string{"-ports", open + ",1,2", "-port-discover", "first"}, 16 * 2, "connects"},
		{"discover only", []string{"-ports", open + ",1,2", "-ports-udp", "9,10", "-port-discover", "only"}, 16 * 2, "connects"},
		{"udp", []string{"-ports", "none", "-ports-udp", "9,10,11"}, 16 * 3, "datagrams"},
		{"-port-threshold", []string{"-ports", open + ",1,2,3,4,5,6", "-port-threshold", "2"}, 16 * 2, "connects"},
	} {
		t.Run(c.name, func(t *testing.T) {
			all := append(append([]string{}, args...), c.extra...)
			est := planCost(t, all...)["ports"]
			if est == nil || stageAmount(est, "estimate", c.what) != c.want {
				t.Fatalf("the plan estimates %v, want %v %s", est, c.want, c.what)
			}
			if est["estimate_at_least"] != true {
				t.Errorf("a floor is not marked: %v", est)
			}
			sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, all...)...)
			if got := stageAmount(stagesOf(t, sum)["ports"], "actual", c.what); got < c.want {
				t.Errorf("the floor is %v %s, the run made %v", c.want, c.what, got)
			}
		})
	}
}

// A CDN's addresses are sent no UDP, and an -port-exclude-cdn scan asks them
// four ports: the plan counts none of the first and four of the second, with no
// connection made.
func TestPortsEstimateKnowsTheCDNAddressesOfARange(t *testing.T) {
	cf := []string{"-cidr", "104.16.0.0/28", "-allow", "104.16.0.0/28", "-sources", "none"}
	if st := planCost(t, append(cf, "-ports", "none", "-ports-udp", "top")...)["ports"]; stageAmount(st, "estimate", "connects") != 0 {
		t.Errorf("UDP to a CDN range is estimated at %v", st)
	}
	if st := planCost(t, append(cf, "-ports", "top-100", "-port-exclude-cdn")...)["ports"]; stageAmount(st, "estimate", "connects") != 16*4 {
		t.Errorf("-port-exclude-cdn on a CDN range is estimated at %v, want %d", st, 16*4)
	}
	if st := planCost(t, append(cf, "-ports", "top-100")...)["ports"]; stageAmount(st, "estimate", "connects") != 16*100 {
		t.Errorf("a CDN range is scanned in full by default: %v", st)
	}
	// A range of a million addresses that holds one: any of them may be a CDN's.
	big := planCost(t, "-cidr", "104.0.0.0/8", "-allow", "104.0.0.0/8", "-sources", "none", "-ports", "top-100", "-port-exclude-cdn", "-ports-udp", "top")["ports"]
	if got := stageAmount(big, "estimate", "connects"); got != float64(1<<24)*4 {
		t.Errorf("a /8 that holds a CDN range, with -port-exclude-cdn: %v, want %d", big, int64(1<<24)*4)
	}
}

// A very large range is counted, not walked.
func TestPortsEstimateOfAHugeRange(t *testing.T) {
	st := planCost(t, "-cidr", "10.0.0.0/8", "-allow", "10.0.0.0/8", "-deny", "10.1.0.0/16", "-sources", "none", "-ports", "top-100")["ports"]
	if got, want := stageAmount(st, "estimate", "connects"), float64((1<<24-1<<16)*100); got != want {
		t.Errorf("a /8 less a /16: %v connects, want %v", got, want)
	}
}

// A floor is never above what the run sent, stage by stage: for each stand-in
// below, what the plan counts for a stage is at most what that stage sent.
func TestEstimateIsAFloorOnStandIns(t *testing.T) {
	var hits atomic.Int64
	plain := juiceShaped(&hits)
	defer plain.Close()
	// A server with an API description: the guesses of one end at the first.
	described := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>api</title><body>hi</body></html>`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`)
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer described.Close()
	loc := func(u string) string { return strings.Replace(u, "127.0.0.1", "localhost", 1) }
	words := wordsFile(t, 12)
	cases := map[string][]string{
		"a plain page":           {"-url", plain.URL + "/", "-allow", "127.0.0.1"},
		"an API description":     {"-url", described.URL + "/", "-allow", "127.0.0.1"},
		"a name and its URL":     {"-url", loc(plain.URL) + "/", "-allow", "localhost", "-allow", "127.0.0.1"},
		"two URLs of one origin": {"-url", plain.URL + "/", "-url", plain.URL + "/app/", "-allow", "127.0.0.1"},
		"-deny-path":             {"-url", plain.URL + "/", "-allow", "127.0.0.1", "-deny-path", "admin|login|swagger", "-dirs", words},
		"-dirs":                  {"-url", plain.URL + "/", "-allow", "127.0.0.1", "-dirs", words, "-dirs-ext", "php"},
		"-known-files":           {"-url", plain.URL + "/", "-allow", "127.0.0.1", "-known-files", "all"},
		"-no-favicon":            {"-url", described.URL + "/", "-allow", "127.0.0.1", "-no-favicon"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			args = append(args, "-sources", "none", "-ledger", "off")
			est := planCost(t, args...)
			sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
			sent := stagesOf(t, sum)
			for stage, st := range est {
				got := sentIn(sent[stage]) + stageAmount(sent[stage], "actual", "dns_queries")
				if want := estimated(st); want > got {
					t.Errorf("%s stage: the floor is %v, the run sent %v (%v)", stage, want, got, st)
				}
			}
		})
	}
}

// The names stage counts a query for each name, one for each zone a wildcard
// is looked for in, and a registrable domain's MX, TXT and NS; every query to
// a resolver is the names stage's whichever collector sent it, so what it sent
// is what the resolver saw and the floor is not above it.
func TestNamesFloorAndItsQueries(t *testing.T) {
	var asked atomic.Int64
	z := fakeZone{a: map[string]string{"a.example.test": "127.0.0.1", "b.example.test": "127.0.0.1", "example.test": "127.0.0.1", "c.d.example.test": "127.0.0.1"}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		asked.Add(1)
		z.handle(w, r)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	resolvers := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(resolvers, []byte(pc.LocalAddr().String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	web := juiceShaped(&hits)
	defer web.Close()
	url := func(host string) []string { return []string{"-url", "http://" + host + ":" + portOfURL(web.URL) + "/"} }
	for _, c := range []struct {
		name  string
		urls  []string
		floor float64
	}{
		{"one name", url("a.example.test"), 2},                                                                                         // the name, and the zone it is in
		{"two names of a zone", append(url("a.example.test"), url("b.example.test")...), 3},                                            // the zone once
		{"a deeper name and the domain", append(append(url("a.example.test"), url("c.d.example.test")...), url("example.test")...), 8}, // 3 names, the zones d.example.test and example.test, and the domain's MX, TXT and NS
	} {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string{}, c.urls...), "-resolvers", resolvers, "-allow", "example.test", "-allow", "127.0.0.1", "-sources", "none", "-ledger", "off", "-no-paths")
			est := planCost(t, args...)["names"]
			if got := stageAmount(est, "estimate", "dns_queries"); got != c.floor {
				t.Errorf("the plan counts %v DNS queries, want %v", got, c.floor)
			}
			asked.Store(0)
			sum := runJSON(t, append([]string{"run", "-db", filepath.Join(t.TempDir(), "w.db")}, args...)...)
			sent := stageAmount(stagesOf(t, sum)["names"], "actual", "dns_queries")
			if sent != float64(asked.Load()) {
				t.Errorf("the names stage sent %v DNS queries, the resolver saw %d", sent, asked.Load())
			}
			if sent < c.floor {
				t.Errorf("the floor is %v DNS queries, the run sent %v", c.floor, sent)
			}
		})
	}
}
