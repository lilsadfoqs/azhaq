package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/fuzz"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/neterr"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
)

// The docs name the encoders -enc takes: the list is the code's, and
// ffuf's htmlescape and htmlunescape are not among them.
func TestFuzzEncodersAreTheListTheDocsName(t *testing.T) {
	raw, err := os.ReadFile("../../docs/commands/fuzz.md")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, "The encoders are") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("the page does not list the encoders")
	}
	list, _, _ := strings.Cut(line, "run in process")
	var named []string
	for _, m := range regexp.MustCompile("`([a-z0-9]+)`").FindAllStringSubmatch(list, -1) {
		named = append(named, m[1])
	}
	slices.Sort(named)
	if have := fuzz.EncoderNames(); !slices.Equal(named, have) {
		t.Errorf("the page names %v, -enc takes %v", named, have)
	}
	for _, name := range []string{"htmlescape", "htmlunescape"} {
		_, errOut, code := cli(t, "fuzz", "-u", "http://127.0.0.1:9/FUZZ", "-w", wlist(t, "a"), "-enc", "FUZZ:"+name)
		if code != exitUsage || !strings.Contains(errOut, fmt.Sprintf("encoder %q is not one of", name)) {
			t.Errorf("%s: exit %d\n%s", name, code, errOut)
		}
	}
}

// With GOMAXPROCS in the environment -rate leaves the number of cores alone,
// without it -rate sizes it.
func TestPortsGOMAXPROCSInTheEnvironmentIsYours(t *testing.T) {
	t.Chdir(t.TempDir())
	args := []string{"ports", "-host", "127.0.0.1", "-p", "1-1500", "-detect", "none", "-silent", "-ledger", "off"}
	was := runtime.GOMAXPROCS(0)
	gc := debug.SetGCPercent(100)
	t.Cleanup(func() { runtime.GOMAXPROCS(was); debug.SetGCPercent(gc) })
	runtime.GOMAXPROCS(3)
	t.Setenv("GOMAXPROCS", "3")
	cli(t, append(slices.Clone(args), "-rate", "5000")...)
	if got := runtime.GOMAXPROCS(0); got != 3 {
		t.Errorf("with GOMAXPROCS=3 in the environment -rate 5000 set %d cores", got)
	}
	t.Setenv("GOMAXPROCS", "")
	cli(t, append(slices.Clone(args), "-rate", "5000")...)
	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Errorf("without GOMAXPROCS in the environment -rate 5000 left %d cores: one core is what 5,000 a second needs", got)
	}
}

// A write's verdict `only its owner writes it` is given when every other
// role's answer is a refusal (a 4xx or a 2xx that says it was denied). A
// redirect is not a refusal: it has verdicts of its own, alone or among
// refusals and 5xx; a 5xx among refusals is the mixed verdict.
func TestRolesOnlyItsOwnerWritesItAlsoWhenTheOthersAreRedirectedOrDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"x"}`)
			return
		}
		switch r.Header.Get("A") {
		case "1": // the owner
			w.WriteHeader(200)
		case "2":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "3":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"error":"access denied"}`)
		case "4":
			w.WriteHeader(500)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	session := func(v string) http.Header { return http.Header{"A": {v}} }
	owner := role{name: "alice", headers: []string{"A: 1"}, session: session("1")}
	bob := role{name: "bob", headers: []string{"A: 2"}, session: session("2")}
	carol := role{name: "carol", headers: []string{"A: 3"}, session: session("3")}
	dave := role{name: "dave", headers: []string{"A: 4"}, session: session("4")}
	req := []writeReq{{owner: "alice", method: "PUT", url: srv.URL + "/api/items/3", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"name":"y"}`), from: "alice.har", status: 200}}
	run := func(roles ...role) roleRow {
		rows, _, err := replayWrites(append([]role{{name: "anon"}, owner}, roles...), req, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%v %+v", err, rows)
		}
		return rows[0]
	}
	if row := run(carol); row.Verdict != verdictWriteOwner || row.Answers["anon"].Status != 404 || !(row.Answers["carol"].Error || row.Answers["carol"].Refusal) {
		t.Errorf("verdict %q, answers %+v: want %q with a 404 and a denied 2xx", row.Verdict, row.Answers, verdictWriteOwner)
	}
	if row := run(bob, carol); row.Verdict != verdictWriteMixedRedirect || row.Answers["bob"].Status != 302 {
		t.Errorf("a redirect among refusals: verdict %q, want %q", row.Verdict, verdictWriteMixedRedirect)
	}
	if row := run(carol, dave); row.Verdict != verdictWriteMixed {
		t.Errorf("a 5xx among refusals: verdict %q, want %q", row.Verdict, verdictWriteMixed)
	}
}

// app126 is a small app whose rows test the default view's folding: a link
// that answers, a route a script calls with POST, a route a description
// lists, a route only a script names that answers 500, one that answers 404,
// and a linked path a -deny-path rule keeps out.
func app126(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>app</title><script src="/app.js"></script></head><body><a href="/linked">l</a><a href="/denied">d</a></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `fetch("/api/called",{method:"POST",body:"x"}); var a="/api/boom"; var b="/api/gone";`)
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/api/described":{"get":{"summary":"lists","responses":{"200":{"description":"ok"}}}}}}`)
		case "/linked", "/api/described", "/denied":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
		case "/api/boom":
			w.WriteHeader(500)
			fmt.Fprint(w, "boom")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A route a script calls with a method, a description lists, a page links
// or a request answered with anything else but 404 stays listed, as does a
// row under -deny-path; one only scripts name that answered 404 is folded.
func TestRunFoldsNeverTheLeadsOrTheEffectOfADenyPathRule(t *testing.T) {
	srv := app126(t)
	t.Chdir(t.TempDir())
	args := []string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-deny-path", "^/denied$", "-ledger", "off", "-no-favicon", "-no-tech"}
	out, errOut, code := cli(t, append(slices.Clone(args), "-json", "-db", "j.db")...)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	fold := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		var row struct{ Key, Fold string }
		if json.Unmarshal([]byte(l), &row) == nil && row.Key != "" {
			fold[strings.TrimPrefix(row.Key, srv.URL)] = row.Fold
		}
	}
	for _, p := range []string{"/linked", "/api/called", "/api/described", "/api/boom", "/denied"} {
		if f, ok := fold[p]; !ok || f != "" {
			t.Errorf("%s: fold %q (a row %v): it is a lead or the effect of a setting, and stays listed", p, f, ok)
		}
	}
	if fold["/api/gone"] != "not-found" {
		t.Errorf("/api/gone, named only by a script and answered 404: fold %q, want not-found (the contrast)", fold["/api/gone"])
	}
	text, errOut, code := cli(t, append(slices.Clone(args), "-db", "t.db")...)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	for _, p := range []string{"/linked", "/api/called", "/api/described", "/api/boom", "/denied"} {
		if !strings.Contains(text, srv.URL+p) {
			t.Errorf("the text map lacks %s:\n%s", p, text)
		}
	}
	if strings.Contains(text, srv.URL+"/api/gone") {
		t.Errorf("the text map lists /api/gone, which only a script names and the server answered 404:\n%s", text)
	}
}

// A row's coverage is `skipped` only for a path a -deny-path rule keeps out,
// a script-named path the catch-all rule held back, or a GET found on the way
// whose own name declares a state change (held back): a POST form, an address outside the scope and a page of another port are
// not. A URL of a host -allow lists with another port only has no row, and
// the summary's skipped names it with that reason.
func TestRunNothingElseMakesARowSkipped(t *testing.T) {
	var bHits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { bHits.Add(1) }))
	defer other.Close()
	var routes []string
	for i := 0; i < 12; i++ {
		routes = append(routes, fmt.Sprintf("'/spa/p%d'", i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>app</title><script src="/app.js"></script></head><body><a href="/denied">d</a><a href="/logout">o</a><a href="http://outside.invalid/x">x</a><form method="post" action="/post"><input name="a"></form></body></html>`)
		case r.URL.Path == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, "var routes=[%s]; fetch(%q);", strings.Join(routes, ","), other.URL+"/other")
		case strings.HasPrefix(r.URL.Path, "/spa/"):
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>Shell</title></head><body><app-root></app-root></body></html>`)
		case r.URL.Path == "/logout":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>Signed out</title></head><body><p>You are signed out. Back to the front page.</p></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	out, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1:"+port, "-sources", "none", "-no-paths", "-no-tech", "-no-favicon",
		"-deny-path", "^/denied$", "-ledger", "off", "-json", "-db", "w.db")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	rep := lastReport(t, errOut)
	covered := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		var row struct{ Key, Coverage string }
		if json.Unmarshal([]byte(l), &row) == nil && row.Key != "" {
			covered[strings.TrimPrefix(row.Key, srv.URL)] = row.Coverage
		}
	}
	held := 0
	for p, c := range covered {
		switch {
		case c != "skipped":
		case p == "/denied":
		case strings.HasPrefix(p, "/spa/"):
			held++
		case p == "/logout":
		default:
			t.Errorf("%s is skipped: only a -deny-path rule, the catch-all hold or a held state-changing GET does that", p)
		}
	}
	if covered["/denied"] != "skipped" || held == 0 {
		t.Errorf("coverage %v: want /denied skipped and some of /spa/ held", covered)
	}
	if covered["/logout"] != "skipped" {
		t.Errorf("the state-changing GET /logout found on the way: coverage %q, want skipped (held back)", covered["/logout"])
	}
	for p := range covered {
		if strings.Contains(p, "outside.invalid") || strings.Contains(p, "/other") || p == "/post" {
			t.Errorf("%s has a row: a POST form is not sent and an outside address is no target", p)
		}
	}
	if bHits.Load() != 0 {
		t.Errorf("the other port got %d requests", bHits.Load())
	}
	reasons := map[string]bool{}
	for _, s := range rep.Skipped {
		reasons[s.Reason] = true
		if s.Reason != neterr.OutOfPortReason && s.Reason != engine.CatchAllHeldReason && s.Reason != "-deny-path ^/denied$" && !egress.IsHeldReason(s.Reason) {
			t.Errorf("the summary's skipped holds %+v", s)
		}
	}
	if !reasons[neterr.OutOfPortReason] || !reasons[engine.CatchAllHeldReason] || !reasons["-deny-path ^/denied$"] {
		t.Errorf("the summary's skipped lacks a reason: %+v", rep.Skipped)
	}
}

// crawl asks every path a script names, as katana does, where run stops
// asking a directory's paths once 3 of them answered with the catch-all
// page; the catch-all answers are rows of their own (coverage catchall),
// which the default list folds into a line.
func TestCrawlAsksEveryPathAndKeepsTheCatchAllAnswersAsRows(t *testing.T) {
	srv, hits := shellApp(t, 20)
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "crawl", "-u", srv.URL+"/", "-allow", "127.0.0.1", "-db", "c.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if n := hits.Load(); n < 120 {
		t.Errorf("%d requests reached the server for 120 script-named paths", n)
	}
	if !strings.Contains(errOut, "folded catchall: ") {
		t.Errorf("the default list does not fold the catch-all answers into a line:\n%s", errOut)
	}
	count := func(coverage string) int {
		out, errOut, code := cli(t, "query", "-db", "c.db", "-coverage", coverage, "-fields", "key", "-json")
		if code != exitOK {
			t.Fatalf("query: exit %d\n%s", code, errOut)
		}
		return strings.Count(out, "/app/")
	}
	if c, k := count("catchall"), count("skipped"); c != 120 || k != 0 {
		t.Errorf("the workspace holds %d catch-all rows of /app/ and %d skipped, want 120 and none", c, k)
	}
}

// With -browser, Chrome opens a view in the path like any page the run
// found, and does not open a view after the hash: for an app that routes by
// the hash it loads the front page once.
func TestRunBrowserOpensViewsInThePathAndNotAfterTheHash(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	for _, c := range []struct {
		name, js string
		views    []string
		want     int // Chrome's page loads of the front page
	}{
		{"path", `(0,o.jsx)(Me,{path:"/admin",element:(0,o.jsx)(Admin,{})});const routes=[{path:"/reports",component:Reports}];createRouter({history:createWebHistory(),routes});`, []string{"/admin", "/reports"}, 1},
		{"hash", "var Hw=[{path:`administration`,component:Su},{path:`basket`,component:Bk}];Ro.forRoot(Hw,{useHash:!0});", nil, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			var mu sync.Mutex
			opened := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
					mu.Lock()
					opened[r.URL.Path]++
					mu.Unlock()
				}
				switch r.URL.Path {
				case "/app.js":
					w.Header().Set("Content-Type", "application/javascript")
					fmt.Fprint(w, c.js)
				case "/", "/admin", "/reports", "/administration", "/basket":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, `<!doctype html><html><head><title>app</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-browser", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-quiet", "-json", "-db", "b.db")
			if code != exitOK {
				t.Skipf("Chrome did not run here: exit %d\n%s", code, errOut)
			}
			mu.Lock()
			defer mu.Unlock()
			if opened["/"] != c.want {
				t.Errorf("Chrome loaded the front page %d times, want %d: %v", opened["/"], c.want, opened)
			}
			if c.name == "path" && (opened["/admin"] != 1 || opened["/reports"] != 1) {
				t.Errorf("Chrome did not open the views in the path once each: %v", opened)
			}
			if c.name == "hash" && len(opened) != 1 {
				t.Errorf("Chrome opened more than the front page of an app that routes by the hash: %v", opened)
			}
		})
	}
}

// The query names of the links on a page are on the links' rows, not the
// page's.
func TestRunQueryNamesOfLinksAreOnTheLinksRowsNotThePages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><title>home</title></head><body><a href="/search?q=1&amp;page=2">s</a></body></html>`)
		default:
			fmt.Fprint(w, "<title>"+r.URL.Path+"</title>")
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	out, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-json", "-db", "q.db")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	params := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		var row struct {
			Key    string
			Params []string
		}
		if json.Unmarshal([]byte(l), &row) == nil && row.Key != "" {
			params[strings.TrimPrefix(row.Key, srv.URL)] = row.Params
		}
	}
	if len(params["/"]) != 0 {
		t.Errorf("the page's row has params %v: the names of its links' queries are the links'", params["/"])
	}
	if got := strings.Join(params["/search?q=1&page=2"], ","); got != "q,page" {
		t.Errorf("the link's row has params %q, want q,page (rows %v)", got, params)
	}
}

// -sweep adds the scope's ranges to the targets as -cidr does for each: with
// -ports they are scanned whole whatever -max-ips says, and without it a
// range is expanded up to -max-ips, the summary saying how much was left.
func TestRunSweepIsCidrForEachRangeAndMaxIPsCutsOnlyWhatIsNotScanned(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	lab := newSweepLab(t)
	run := func(name string, args ...string) (map[string]any, map[string]bool) {
		led := filepath.Join(dir, name+".ledger.jsonl")
		_, errOut, code := cli(t, append([]string{"run", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", led, "-json", "-quiet", "-db", name + ".db"}, args...)...)
		if code != exitOK && code != exitPartial {
			t.Fatalf("%s: exit %d\n%s", name, code, errOut)
		}
		asked := map[string]bool{}
		if err := ledger.Read(led, func(e ledger.Entry) error {
			if m := regexp.MustCompile(`127\.7\.7\.\d+`).FindString(e.Target); m != "" {
				asked[m] = true
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return sumMap(t, errOut), asked
	}
	counts := func(sum map[string]any) string {
		c, _ := sum["counts"].(map[string]any)
		return fmt.Sprintf("addresses %v ports %v", c["addresses"], c["ports"])
	}
	swept, askedSwept := run("swept", "-allow", "127.7.7.0/29", "-sweep", "-ports", lab.port)
	cidr, askedCidr := run("cidr", "-allow", "127.7.7.0/29", "-cidr", "127.7.7.0/29", "-ports", lab.port)
	if counts(swept) != "addresses 3 ports 3" || counts(swept) != counts(cidr) || len(askedSwept) != 8 || len(askedCidr) != 8 {
		t.Errorf("-sweep: %s, %d addresses asked; -cidr: %s, %d asked: want the same, 8 asked, the 3 open ports", counts(swept), len(askedSwept), counts(cidr), len(askedCidr))
	}
	// With -ports: all 256 addresses are scanned, though -max-ips is 4.
	big, askedBig := run("big", "-allow", "127.7.7.0/24", "-sweep", "-ports", lab.port, "-max-ips", "4")
	if counts(big) != "addresses 3 ports 3" || len(askedBig) != 256 || strings.Contains(notesOf(big), "expanded") {
		t.Errorf("-sweep of a /24 with -ports and -max-ips 4: %s, %d addresses asked, notes %v", counts(big), len(askedBig), big["notes"])
	}
	// With -ports none (no port is asked): 4 of the 16 addresses, and the summary says so.
	cut, askedCut := run("cut", "-allow", "127.7.7.0/28", "-sweep", "-ports", "none", "-max-ips", "4")
	if c, _ := cut["counts"].(map[string]any); c["addresses"] != float64(4) || len(askedCut) != 4 || !strings.Contains(notesOf(cut), "expanded 4 of 16 addresses (-max-ips 4 for the run)") {
		t.Errorf("-sweep of a /28 with -ports none and -max-ips 4: %s, %d addresses asked, notes %v", counts(cut), len(askedCut), cut["notes"])
	}
}

// The connects of the next port pass are N times the addresses the scan
// asked, N being the ports not asked, counted as plan counts a port scan (a
// connect for each port of each address): what this run's scan estimated
// and the pass add up to the whole range of each address. The banner and
// protocol probes of an open port are not in it: the run's own scan sent
// more connects than its estimate by them.
func TestTheNextPortPassCountsConnectsAsPlanDoesAndLeavesTheProbesOut(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	port := portOfURL(srv.URL)
	t.Chdir(t.TempDir())
	_, errOut, code := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-paths", "-no-tech", "-no-favicon", "-ledger", "off", "-db", "n.db", "-ports", "top-100,"+port, "-quiet", "-json")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	sum := sumMap(t, errOut)
	ports := stagesOf(t, sum)["ports"]
	est, actual := stageAmount(ports, "estimate", "connects"), stageAmount(ports, "actual", "connects")
	var pass string
	for _, n := range sum["next"].([]any) {
		if s := n.(string); strings.Contains(s, "next pass, not run: the other ") {
			pass = s
		}
	}
	m := regexp.MustCompile(`the other (\d+) of the 65535 TCP ports were not asked on 1 address: (\d+) connects`).FindStringSubmatch(pass)
	if m == nil {
		t.Fatalf("no wider pass in next: %v", sum["next"])
	}
	other, _ := strconv.Atoi(m[1])
	c, _ := strconv.Atoi(m[2])
	if c != other*1 || float64(c)+est != 65535 {
		t.Errorf("the pass says %d connects for %d ports on 1 address, and the scan estimated %v: want N times the addresses, N and the estimate making the 65535", c, other, est)
	}
	if actual <= est {
		t.Errorf("the scan sent %v connects for an estimate of %v: the probes of the open port come on top of the estimate", actual, est)
	}
	if _, cost := portsPass(100, 2, 0); cost.Connects != 2*(65535-100) {
		t.Errorf("two addresses: %v", cost)
	}
	if _, with := portsPass(100, 2, 5); with.Connects != 2*(65535-100) {
		t.Errorf("open ports found change the connects of the pass to %v", with)
	}
}

// With -advisories -advisories-confirm, -verify sends nothing more for an
// advisory lead: the server gets the same requests with and without it, and
// each lead's verify label follows from the lead's one confirmation read
// (observed: proved; inferred: conditional).
func TestVerifySendsNothingMoreForAnAdvisoryLead(t *testing.T) {
	run := func(extra ...string) ([]string, report) {
		egress.Reset()
		t.Cleanup(egress.Reset)
		cs := newCountingServer(t, true)
		db := filepath.Join(t.TempDir(), "w.db")
		args := append([]string{"-url", cs.URL + "/", "-db", db, "-json", "-quiet", "-depth", "0", "-no-paths", "-no-tech", "-no-favicon",
			"-advisories", "-advisories-confirm", "-advisory-source", writeAdvFixture(t, advFixture)}, extra...)
		_, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
		if err != nil {
			t.Fatalf("%v\n%s", err, errOut)
		}
		got := cs.requests()
		slices.Sort(got)
		return got, withStoredAdvisories(t, db, lastReport(t, errOut))
	}
	without, repA := run()
	with, repB := run("-verify")
	if !slices.Equal(without, with) || len(without) == 0 {
		t.Errorf("the server saw %v without -verify and %v with it", without, with)
	}
	label := map[string]string{"observed": "version-read", "inferred": "conditional"}
	// One lead for the service, and one verify row for it: the top advisory's.
	if len(repA.Advisories) != 1 || len(repA.Advisories[0].Advisories) != 2 || len(repB.Verify) != 1 {
		t.Fatalf("leads %+v, verify results %+v", repA.Advisories, repB.Verify)
	}
	l := repA.Advisories[0]
	got := repB.Verify[0]
	if got.AdvisoryID != l.AdvisoryID || got.Label != label[l.Confidence] || got.Label == "" {
		t.Errorf("%s: lead %q, verify %s %q, want %q", l.AdvisoryID, l.Confidence, got.AdvisoryID, got.Label, label[l.Confidence])
	}
	if !strings.Contains(got.Evidence, "2 advisories in all match") {
		t.Errorf("the verify row does not say the service has 2 advisories: %q", got.Evidence)
	}
}

// A proved result names the read it made and nothing about exploitability,
// which is not tested: its request is the read, the one request sent is
// that read, no printed field calls the service exploitable, and the summary
// says what proved names.
func TestAProvedResultNamesTheReadAndNeverExploitability(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newRedisFixture(t, redisInfoResp())
	out, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", strconv.Itoa(fx.port), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-verify"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	if len(rep.Verify) != 1 || rep.Verify[0].Label != "proved" || rep.Verify[0].Request != "INFO server" {
		t.Fatalf("verify results %+v, want one proved by INFO server", rep.Verify)
	}
	raw, _ := json.Marshal(rep.Verify)
	if re := regexp.MustCompile(`(?i)exploit|vulnerab|payload`); re.Match(raw) || re.MatchString(out) {
		t.Errorf("a result speaks of exploitability: %s", raw)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "proved names that read only, never exploitability") {
		t.Errorf("the summary does not say what proved names: %q", rep.Notes)
	}
}

// The severity printed ranks how directly the read shows the fact: a read of
// a version or a banner is info, a version a service stated in an advisory's range
// info too, a conditional low;
// it is not a CVSS score (no result has one).
func TestVerifySeverityIsTheStatedRankingNotACVSSScore(t *testing.T) {
	for _, c := range []struct{ kind, label, want string }{
		{verify.KindUnauthenticatedRead, verify.Proved, "info"},
		{verify.KindUnauthenticatedHandshake, verify.Proved, "info"},
		{verify.KindAdvisoryPrecond, verify.VersionRead, "info"},
		{verify.KindUnauthenticatedRead, verify.Conditional, "low"},
		{verify.KindAdvisoryPrecond, verify.Conditional, "low"},
		{verify.KindUnauthenticatedRead, verify.VersionOnly, "info"},
		{verify.KindAdvisoryPrecond, verify.VersionOnly, "info"},
	} {
		if got := verify.SeverityOf(verify.Result{Kind: c.kind, Label: c.label}); got != c.want {
			t.Errorf("%s %s: severity %q, want %q", c.kind, c.label, got, c.want)
		}
	}
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newRedisFixture(t, redisInfoResp())
	_, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", strconv.Itoa(fx.port), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-verify"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	raw, _ := json.Marshal(rep.Verify)
	if len(rep.Verify) != 1 || rep.Verify[0].Severity != "info" || strings.Contains(strings.ToLower(string(raw)), "cvss") {
		t.Errorf("a proved unauthenticated Redis read: %s, want severity info (the read shows a version) and no CVSS", raw)
	}
}

// A verification read the scope refuses or a limit stops is a note, not a
// failure; one that gets no answer is a failure, and the run exits 3.
func TestVerifyAReadTheScopeRefusesIsANoteAndOneWithNoAnswerIsAFailure(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fx := newRedisFixture(t, redisInfoResp())
	egress.SetScope(func(h string) bool { return false })
	results, failures, note := verifyStage(context.Background(), st, redisObs(fx.port, ""), nil, "azhaq run -verify")
	if len(failures) != 0 || len(results) != 0 || fx.infoCount() != 0 || !strings.Contains(note, "1 verification reads were not sent: their targets are outside the scope") {
		t.Errorf("a read outside the scope: results %v, failures %v, %d reads, note %q", results, failures, fx.infoCount(), note)
	}

	// No answer: the service takes the connection and closes it.
	egress.Reset()
	mute := newRedisFixture(t, "")
	results, failures, _ = verifyStage(context.Background(), st, redisObs(mute.port, ""), nil, "azhaq run -verify")
	if len(results) != 0 || len(failures) != 1 || failures[0].Collector != "azhaq-verify" || failures[0].Count != 1 {
		t.Errorf("a read with no answer: results %v, failures %+v", results, failures)
	}
}

// A Redis that answers what the scan asks and then goes mute: the verify
// read gets no answer, and ports exits 3 with the failure named.
func TestPortsVerifyReadWithNoAnswerExitsThree(t *testing.T) {
	var accepted, answerFirst atomic.Int32
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
			n := accepted.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				c.Read(buf)
				if limit := answerFirst.Load(); limit == 0 || n <= limit {
					_, _ = c.Write([]byte(redisInfoResp()))
				}
			}(c)
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	run := func() (int, report) {
		egress.Reset()
		accepted.Store(0)
		_, errOut, code := cli(t, "ports", "-host", "127.0.0.1", "-p", port, "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-verify", "-ledger", "off")
		return code, lastReport(t, errOut)
	}
	t.Cleanup(egress.Reset)
	if code, rep := run(); code != exitOK || len(rep.Verify) != 1 {
		t.Fatalf("a service that answers: exit %d, %d verify results", code, len(rep.Verify))
	}
	answerFirst.Store(accepted.Load() - 1) // every connect but the verify read (the last) is answered
	code, rep := run()
	failed := false
	for _, f := range rep.Failed {
		failed = failed || f.Collector == "azhaq-verify" && strings.Contains(f.Error, "got no answer")
	}
	if code != exitPartial || !failed || len(rep.Verify) != 0 {
		t.Errorf("exit %d, failed %+v, verify %+v: want exit %d with the verification read named", code, rep.Failed, rep.Verify, exitPartial)
	}
}
