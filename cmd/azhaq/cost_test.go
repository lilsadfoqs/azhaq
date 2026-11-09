package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/browser"
)

// costFactor is how far from what a fixture was sent the estimate of its
// web map may be: the page, the favicon and the built-in paths are counted,
// the links, scripts and API calls the pages lead to are not (they are named
// in not_counted), so the estimate is the lower one.
const costFactor = 4

// roleMapsFactor is the same for the maps of the roles of a fixture with a
// sign-in: its pages draw their styles, scripts and images, which no floor counts.
const roleMapsFactor = 6

// juiceShaped is a single-page app like Juice Shop: one page, one script that
// names a route table and API calls, and a REST API behind it. hits counts
// every request the server gets: the count a proxy in front would log.
func juiceShaped(hits *atomic.Int64) *httptest.Server {
	var js strings.Builder
	js.WriteString("var routes=[")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&js, "{path:'page%d',component:1},", i)
	}
	js.WriteString("];")
	for _, p := range []string{"/api/Products", "/api/Challenges", "/api/Quantitys", "/rest/products/search?q=", "/rest/user/whoami", "/rest/basket/1", "/api/Feedbacks", "/rest/admin/application-version"} {
		fmt.Fprintf(&js, "fetch('%s');", p)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Shop</title><body><app-root></app-root><script src="/main.js"></script></body></html>`)
		case r.URL.Path == "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, js.String())
		case strings.HasPrefix(r.URL.Path, "/api/"), strings.HasPrefix(r.URL.Path, "/rest/"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"success","data":[{"id":1,"name":"x"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

// A summary read as plain JSON, so that the tests need nothing of the code
// they are about but the command line.

// stageAmount is an amount of the stage (a stage's "estimate" or "actual"),
// by field; zero for none.
func stageAmount(st map[string]any, which, field string) float64 {
	m, _ := st[which].(map[string]any)
	n, _ := m[field].(float64)
	return n
}

// stagesOf is the stages of a summary's cost, by name.
func stagesOf(t *testing.T, sum map[string]any) map[string]map[string]any {
	t.Helper()
	c, _ := sum["cost"].(map[string]any)
	if c == nil {
		t.Fatalf("the summary has no cost: %v", sum)
	}
	out := map[string]map[string]any{}
	list, _ := c["stages"].([]any)
	for _, s := range list {
		st := s.(map[string]any)
		out[st["stage"].(string)] = st
	}
	return out
}

// sentIn is requests and connects a stage sent, as the summary counts them.
func sentIn(st map[string]any) float64 {
	return stageAmount(st, "actual", "requests") + stageAmount(st, "actual", "connects")
}

// runJSON runs azhaq with -json and returns its summary.
func runJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	_, errOut, _ := cli(t, append(args, "-json")...)
	return sumMap(t, errOut)
}

// The stages add up to the summary: what they sent is its requests and its DNS
// queries, and the server saw as many.
func stagesAddUp(t *testing.T, sum map[string]any, served int64) {
	t.Helper()
	var sent, dns float64
	for _, st := range stagesOf(t, sum) {
		sent += sentIn(st)
		dns += stageAmount(st, "actual", "dns_queries")
	}
	if int64(sent) != int64(sum["requests"].(float64)) || (served >= 0 && int64(sent) != served) {
		t.Errorf("the stages sent %v, the summary says %v requests, the server saw %d", sent, sum["requests"], served)
	}
	if want, _ := sum["dns_queries"].(float64); dns != want {
		t.Errorf("the stages sent %v DNS queries, the summary says %v", dns, want)
	}
}

// wordsFile is a wordlist of n words.
func wordsFile(t *testing.T, n int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "word%d\n", i)
	}
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func portOfURL(u string) string { return u[strings.LastIndex(u, ":")+1:] }

// plan says, for each stage, what the flags and the targets fix: the page and
// the favicon and the built-in paths of a web service, a connect for each
// port, the words of a sweep and of a brute force, the source queries.
func TestPlanEstimatesEachStage(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	args := []string{"plan", "-url", srv.URL + "/", "-domain", "example.com", "-allow", "127.0.0.1", "-allow", "example.com", "-sources", "none",
		"-dirs", wordsFile(t, 40), "-dirs-ext", "php,bak", "-dns-brute", wordsFile(t, 5), "-ports", "1000-1600," + portOfURL(srv.URL)}
	out, _, _ := cli(t, append(args, "-json")...)
	var p map[string]any
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	est, _ := p["estimate"].(map[string]any)
	if est == nil {
		t.Fatalf("the plan has no estimate: %s", out)
	}
	byStage := map[string]map[string]any{}
	for _, s := range est["stages"].([]any) {
		st := s.(map[string]any)
		byStage[st["stage"].(string)] = st
	}
	for _, c := range []struct {
		stage, field string
		want         float64
	}{
		{"web", "requests", 26},     // the page and the 25 built-in paths that no answer skips; the favicon and the 26 guesses of an API description are not certain
		{"ports", "connects", 602},  // 601 ports and the one that is named twice is once; the port of the URL's host
		{"fuzz", "requests", 126},   // 40 words and 2 extensions, and 6 calibration probes
		{"names", "dns_queries", 5}, // one query for each word
	} {
		st := byStage[c.stage]
		if st == nil {
			t.Errorf("no %s stage in the estimate: %s", c.stage, out)
			continue
		}
		if got := stageAmount(st, "estimate", c.field); got != c.want {
			t.Errorf("%s stage: %s estimated %v, want %v", c.stage, c.field, got, c.want)
		}
	}
	if st := byStage["web"]; st != nil {
		if cols, _ := st["collectors"].([]any); len(cols) != 2 {
			t.Errorf("the web stage lists its collectors, http and paths: %v", st["collectors"])
		}
		if st["not_counted"] == nil || st["estimate_at_least"] != true {
			t.Errorf("the web stage does not say what it leaves out: %v", st)
		}
	}
	if _, ok := byStage["sources"]; ok {
		t.Errorf("-sources none asks no source, and the estimate has a sources stage")
	}
	// The favicon is not in a floor (it is one of the paths, or an icon the page names, or none), so -no-favicon changes nothing in it.
	var q map[string]any
	out, _, _ = cli(t, "plan", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-no-favicon", "-json")
	_ = json.Unmarshal([]byte(out), &q)
	if got := stageAmount(q["estimate"].(map[string]any)["stages"].([]any)[0].(map[string]any), "estimate", "requests"); got != 26 {
		t.Errorf("-no-favicon: the web stage is estimated at %v requests, want 26", got)
	}
	text, _, _ := cli(t, "plan", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none")
	if !strings.Contains(text, "estimate: 26 requests") || !strings.Contains(text, "web ") {
		t.Errorf("the text plan does not print the estimate by stage:\n%s", text)
	}
	if hits.Load() != 0 {
		t.Errorf("a plan sent %d requests", hits.Load())
	}
}

// What a run sent, stage by stage, is what the summary counts and what the
// server saw; the counted stages come out as estimated, the web map within a
// stated factor, since what its pages lead to is not counted before.
func TestRunCostByStageOnAJuiceShopShapedApp(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	port := portOfURL(srv.URL)
	sum := runJSON(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", filepath.Join(t.TempDir(), "w.db"),
		"-dirs", wordsFile(t, 40), "-dirs-ext", "php,bak", "-ports", "1000-1600,"+port, "-port-detect", "none")
	st := stagesOf(t, sum)
	// The server saw the web stages' requests, and the open port's connect that
	// is answered (-port-detect none sends nothing on it).
	var web float64
	for _, name := range []string{"web", "fuzz"} {
		web += sentIn(st[name])
	}
	if int64(web) != hits.Load() {
		t.Errorf("the map and dirs stages sent %v requests, the server saw %d", web, hits.Load())
	}
	stagesAddUp(t, sum, -1)
	m := st["web"]
	if est, got := stageAmount(m, "estimate", "requests"), stageAmount(m, "actual", "requests"); got < est || got > costFactor*est {
		t.Errorf("map stage: estimated %v requests, sent %v: not within a factor of %d, from above", est, got, costFactor)
	}
	if est, got := stageAmount(st["ports"], "estimate", "connects"), stageAmount(st["ports"], "actual", "connects"); got != est {
		t.Errorf("ports stage: estimated %v connects, sent %v", est, got)
	}
	if est, got := stageAmount(st["fuzz"], "estimate", "requests"), stageAmount(st["fuzz"], "actual", "requests"); got != est {
		t.Errorf("dirs stage: estimated %v requests, sent %v", est, got)
	}
}

// The summary in text lists each stage with its estimate beside what it sent.
func TestRunSummaryTextHasTheCostByStage(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	_, errOut, _ := cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", filepath.Join(t.TempDir(), "w.db"), "-ledger", "off")
	if !strings.Contains(errOut, "cost: web: sent 83 requests (estimated 26 requests and what the answers lead to; no ceiling (-max-requests sets one))") {
		t.Errorf("the summary does not set the estimate beside what was sent:\n%s", errOut)
	}
}

// A run says what it will send before it sends it when that is not small, and
// not under -quiet or -json, whose stderr is the summary alone.
func TestRunSaysItsEstimateFirstWhenLarge(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	big := []string{"run", "-url", srv.URL + "/", "-allow", "127.0.0.1", "-sources", "none", "-ledger", "off", "-no-paths", "-ports", "1000-2500," + portOfURL(srv.URL), "-port-detect", "none"}
	_, errOut, _ := cli(t, append(big, "-db", filepath.Join(t.TempDir(), "a.db"))...)
	before, _, found := strings.Cut(errOut, "azhaq run:")
	if !found || !strings.Contains(before, "before sending, the run is estimated at ") || !strings.Contains(before, "1502 connects") {
		t.Errorf("a run of 1500 connects does not say so before it sends:\n%s", errOut)
	}
	for _, quiet := range []string{"-quiet", "-json"} {
		_, errOut, _ = cli(t, append(big, quiet, "-db", filepath.Join(t.TempDir(), "b.db"))...)
		if strings.Contains(errOut, "before sending") {
			t.Errorf("%s: the estimate is printed before the summary:\n%s", quiet, errOut)
		}
	}
	_, errOut, _ = cli(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-ledger", "off", "-db", filepath.Join(t.TempDir(), "c.db"))
	if strings.Contains(errOut, "before sending") {
		t.Errorf("a run of about 50 requests says its estimate first:\n%s", errOut)
	}
}

// A request budget that stops a run says in which stage and what each stage
// had sent, and the resume command.
func TestRunStopNamesTheStage(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "w.db")
	sum := runJSON(t, "run", "-url", srv.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", db, "-ledger", "off",
		"-ports", "1000-1100,"+portOfURL(srv.URL), "-port-detect", "none", "-max-requests", "40")
	stopped, _ := sum["stopped"].(string)
	if !strings.Contains(stopped, "reached in the ") || !strings.Contains(stopped, "sent by stage: ") {
		t.Errorf("the stop does not name the stage that reached the budget: %q", stopped)
	}
	if r, _ := sum["resume"].(string); !strings.HasPrefix(r, "azhaq resume -db "+db) {
		t.Errorf("the stop has no resume command: %q", r)
	}
	var sent float64
	for _, s := range stagesOf(t, sum) {
		sent += sentIn(s)
	}
	if sent != 40 {
		t.Errorf("the stages sent %v, the budget is 40", sent)
	}
}

// vampiShaped is a books API like VAmPI: a bearer token names the user, who
// reads the list and each book, his own and others'.
func vampiShaped(hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer t-")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/books/v1":
			fmt.Fprint(w, `{"Books":[{"book_title":"b1","user":"alice"},{"book_title":"b2","user":"bob"}]}`)
		case strings.HasPrefix(r.URL.Path, "/books/v1/"):
			if user == "" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"status":"fail","message":"Token required"}`)
				return
			}
			fmt.Fprintf(w, `{"book_title":%q,"owner":"alice","secret":"s-%s"}`, strings.TrimPrefix(r.URL.Path, "/books/v1/"), user)
		case r.URL.Path == "/me":
			if user == "" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"status":"fail"}`)
				return
			}
			fmt.Fprintf(w, `{"username":%q}`, user)
		default:
			http.NotFound(w, r)
		}
	}))
}

// roles has stages of its own. Its plan counts what the histories fix: the
// pages each role's history reads, and what the replay asks of the roles that
// did not reach them; the run then sends as much, the replay more by the
// objects its answers name and the checks of the sessions.
func TestRolesCostByStageOnAVAmPIShapedAPI(t *testing.T) {
	var hits atomic.Int64
	srv := vampiShaped(&hits)
	defer srv.Close()
	alice := writeHAR(t, "alice.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/books/v1", "", 200, "Authorization", "Bearer t-alice"),
		harEntry("2026-10-29T10:00:01.000Z", "GET", srv.URL+"/books/v1/b1", "", 200, "Authorization", "Bearer t-alice"),
		harEntry("2026-10-29T10:00:02.000Z", "GET", srv.URL+"/me", "", 200, "Authorization", "Bearer t-alice"))
	bob := writeHAR(t, "bob.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", srv.URL+"/books/v1", "", 200, "Authorization", "Bearer t-bob"),
		harEntry("2026-10-29T10:00:01.000Z", "GET", srv.URL+"/books/v1/b2", "", 200, "Authorization", "Bearer t-bob"),
		harEntry("2026-10-29T10:00:02.000Z", "GET", srv.URL+"/me", "", 200, "Authorization", "Bearer t-bob"))
	flags := []string{"-har", "alice=" + alice, "-har", "bob=" + bob}

	// plan roles, and roles -plan, send nothing.
	for _, args := range [][]string{append([]string{"plan", "roles"}, flags...), append([]string{"roles", "-plan"}, flags...)} {
		out, _, _ := cli(t, append(args, "-json")...)
		var p map[string]any
		if err := json.Unmarshal([]byte(out), &p); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		st := map[string]map[string]any{}
		for _, s := range p["estimate"].(map[string]any)["stages"].([]any) {
			st[s.(map[string]any)["stage"].(string)] = s.(map[string]any)
		}
		if got := stageAmount(st["history reads"], "estimate", "requests"); got != 6 {
			t.Errorf("%v: the history reads are estimated at %v requests, want 6", args[:2], got)
		}
		// 3 pages and the books each read, asked of the roles that did not: anon asks 4 pages,
		// alice and bob the 2 their histories hold only for the other.
		if got := stageAmount(st["replay"], "estimate", "requests"); got != 6 {
			t.Errorf("%v: the replay is estimated at %v requests, want 6", args[:2], got)
		}
		if hits.Load() != 0 {
			t.Fatalf("%v sent %d requests", args[:2], hits.Load())
		}
	}
	text, _, _ := cli(t, append([]string{"plan", "roles"}, flags...)...)
	if !strings.Contains(text, "history reads") || !strings.Contains(text, "replay") || !strings.Contains(text, "estimate: ") {
		t.Errorf("the text plan does not list the stages:\n%s", text)
	}

	sum := runJSON(t, append([]string{"roles", "-dir", t.TempDir()}, flags...)...)
	st := stagesOf(t, sum)
	stagesAddUp(t, sum, hits.Load())
	if est, got := stageAmount(st["history reads"], "estimate", "requests"), stageAmount(st["history reads"], "actual", "requests"); got != est {
		t.Errorf("history reads: estimated %v, sent %v", est, got)
	}
	if est, got := stageAmount(st["replay"], "estimate", "requests"), stageAmount(st["replay"], "actual", "requests"); got < est || got > costFactor*est {
		t.Errorf("replay: estimated %v requests, sent %v: not within a factor of %d, from above", est, got, costFactor)
	}
}

// dvwaShaped is a PHP app like DVWA: a form sign-in with a CSRF token, then
// pages with styles, a script and an image.
func dvwaShaped(hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		loggedIn := strings.Contains(r.Header.Get("Cookie"), "sid=")
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "index.php", http.StatusFound)
		case "/index.php":
			if !loggedIn {
				http.Redirect(w, r, "login.php", http.StatusFound)
				return
			}
			fmt.Fprint(w, `<html><head><link rel=stylesheet href="/css/main.css"><script src="/js/dvwa.js"></script></head><body><img src="/images/logo.png"><a href="/vulnerabilities/">v</a></body></html>`)
		case "/login.php":
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x", Path: "/"})
			if r.Method == http.MethodPost {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s1", Path: "/"})
				http.Redirect(w, r, "index.php", http.StatusFound)
				return
			}
			fmt.Fprint(w, `<html><head><link rel=stylesheet href="/css/login.css"></head><body><img src="/images/login_logo.png">
<form action="login.php" method=post><input name=username><input type=password name=password><input type=submit name=Login value=Login><input type=hidden name=user_token value=abc></form></body></html>`)
		case "/css/login.css", "/css/main.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `body{margin:0}`)
		case "/js/dvwa.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `window.x=1`)
		case "/images/logo.png", "/images/login_logo.png", "/favicon.ico":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("\x89PNG\r\n\x1a\n"))
		default:
			http.NotFound(w, r)
		}
	}))
}

// A roles run with a sign-in has a stage for it, and one for each role's map.
func TestRolesCostByStageOnADVWAShapedApp(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var hits atomic.Int64
	srv := dvwaShaped(&hits)
	defer srv.Close()
	args := []string{"roles", "-dir", t.TempDir(), "-login", srv.URL + "/login.php", "-role", "anon", "-role-login", "admin=admin:password",
		"--", "-url", srv.URL + "/", "-no-paths", "-depth", "0", "-allow", strings.TrimPrefix(srv.URL, "http://")}
	_, errOut, _ := cli(t, append([]string{"roles", "-json"}, args[1:]...)...)
	sum := sumMap(t, errOut)
	st := stagesOf(t, sum)
	stagesAddUp(t, sum, hits.Load())
	in := st["sign-in"]
	if est, got := stageAmount(in, "estimate", "requests"), stageAmount(in, "actual", "requests"); est != 3 || got < est || got > costFactor*est {
		t.Errorf("sign-in: estimated %v requests, sent %v: not within a factor of %d, from above", est, got, costFactor)
	}
	maps := st["role maps"]
	if est, got := stageAmount(maps, "estimate", "requests"), stageAmount(maps, "actual", "requests"); est == 0 || got < est || got > roleMapsFactor*est {
		t.Errorf("role maps: estimated %v requests, sent %v: not within a factor of %d, from above", est, got, roleMapsFactor)
	}
}

// A command-wide budget spent while Chrome signs in says so: the stage, and
// what each stage had sent, in the error and in the summary.
func TestRolesBudgetSpentWhileSigningInNamesTheStage(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	var hits atomic.Int64
	srv := dvwaShaped(&hits)
	defer srv.Close()
	args := []string{"roles", "-dir", t.TempDir(), "-login", srv.URL + "/login.php", "-role", "anon", "-role-login", "admin=admin:password",
		"--", "-url", srv.URL + "/", "-no-paths", "-depth", "0", "-allow", strings.TrimPrefix(srv.URL, "http://"), "-max-requests", "9"}
	_, errOut, code := cli(t, args...)
	if code != exitLimit || !strings.Contains(errOut, "the budget was reached in the sign-in stage; by stage: sign-in ") {
		t.Errorf("exit %d, and the error does not name the stage:\n%s", code, errOut)
	}
	_, errOut, _ = cli(t, append([]string{"roles", "-json"}, args[1:]...)...)
	sum := sumMap(t, errOut)
	if got := sentIn(stagesOf(t, sum)["sign-in"]); got == 0 {
		t.Errorf("the summary of the failed run has no sign-in stage: %v", sum["cost"])
	}
}

// Behind the counting reverse proxy (bench/truth/ledger/countproxy.py), the
// requests it logs are the ones the stages say they sent, and the estimate of
// the map is within the stated factor of them.
func TestStagesAddUpToWhatTheCountProxyLogged(t *testing.T) {
	var hits atomic.Int64
	srv := juiceShaped(&hits)
	defer srv.Close()
	proxy, logged := startCountProxy(t, srv)
	sum := runJSON(t, "run", "-url", "http://"+proxy+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", filepath.Join(t.TempDir(), "w.db"))
	stagesAddUp(t, sum, int64(logged()))
	m := stagesOf(t, sum)["web"]
	if est, got := stageAmount(m, "estimate", "requests"), float64(logged()); got < est || got > costFactor*est {
		t.Errorf("map stage: estimated %v requests, the proxy logged %v: not within a factor of %d, from above", est, got, costFactor)
	}
}
