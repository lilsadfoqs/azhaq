package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"time"
)

// 1. A plain map: only reads reach the site, and the summary's requests, the
// ledger's lines and what the site saw are the same set.
func (c *checklist) mapAndCounts() {
	db := c.fresh("map")
	r, t := c.runTally(db, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json")
	probs := t.problems()
	if r.exit != 0 {
		probs = append(probs, fmt.Sprintf("exit %d, a complete run exits 0", r.exit))
	}
	clCheck("run: summary = ledger = what the site saw, exit 0", probs, "summary %d, ledger %d, site %d", t.summary, len(t.ledger), len(t.counter))
	w := writes(c.site.methods())
	if len(t.counter) < 5 {
		w = append(w, fmt.Sprintf("only %d requests arrived: nothing was mapped", len(t.counter)))
	}
	if n := c.site.trapHits.Load(); n > 0 {
		w = append(w, fmt.Sprintf("%d requests reached the host outside the scope", n))
	}
	clCheck("a plain map sends reads only, though the page, its script and its API description name writes and a GraphQL endpoint", w, "methods %v; %d requests; the form, POST and DELETE routes and /graphql were mapped, not sent", c.site.methods(), len(t.counter))
	// The ledger verifies, and the summary command counts what the run did.
	led := db + ".ledger.jsonl"
	var vp []string
	if out, err := exec.Command(azhaq, "ledger", "-verify", led).CombinedOutput(); err != nil {
		vp = append(vp, fmt.Sprintf("ledger -verify: %v %s", err, clip(string(out), 120)))
	}
	if raw, err := os.ReadFile(led); err == nil && len(raw) > 100 {
		bad := c.file("tampered.ledger.jsonl")
		_ = os.WriteFile(bad, []byte(strings.Replace(string(raw), `"GET"`, `"PUT"`, 1)), 0o644)
		if err := exec.Command(azhaq, "ledger", "-verify", bad).Run(); exitOf(err) != 3 {
			vp = append(vp, fmt.Sprintf("a ledger with an edited line verified, exit %d, want 3", exitOf(err)))
		}
	}
	clCheck("ledger -verify accepts the run's ledger and refuses an edited one with exit 3", vp, "%s", led)
}

func exitOf(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// 2. Writes go only with their flags, and only the method the flag is for.
func (c *checklist) writesOnlyWithFlags() {
	words := c.file("params.txt")
	must(os.WriteFile(words, []byte("debug\nq\nid\n"), 0o644))
	cases := []struct {
		name, method, path string
		args               []string
	}{
		{"-submit-forms sends the form's POST", "POST", "/submit", []string{"-submit-forms"}},
		{"-graphql sends the introspection POST", "POST", "/graphql", []string{"-graphql"}},
		{"-params-writes lets -params-method POST send bodies", "POST", "/", []string{"-params", words, "-params-method", "POST", "-params-writes"}},
	}
	for _, k := range cases {
		db := c.fresh("write")
		args := append([]string{"run", "-url", c.site.origin + "/", "-db", db, "-json"}, k.args...)
		azExec(c.dir, 5*time.Minute, args...)
		settle()
		var probs []string
		got := c.site.methods()
		if got[k.method] == 0 {
			probs = append(probs, fmt.Sprintf("no %s arrived with the flag; methods %v", k.method, got))
		}
		for _, w := range writes(got) {
			if !strings.HasPrefix(w, k.method+" ") {
				probs = append(probs, "another write arrived: "+w)
			}
		}
		clCheck("writes: "+k.name+", and no other write", probs, "methods %v", got)
	}
	// Without -params-writes a body search is refused: nothing is sent.
	db := c.fresh("write")
	r := azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json", "-params", words, "-params-method", "POST")
	settle()
	probs := writes(c.site.methods())
	if r.exit != 2 {
		probs = append(probs, fmt.Sprintf("exit %d, want 2 (a usage error: -params-writes was not given)", r.exit))
	}
	clCheck("writes: -params-method POST without -params-writes is refused and sends nothing", probs, "exit %d; %s", r.exit, clip(lastLine(r.stderr), 120))
}

// 3. -deny-path keeps paths out of every request; without it they are asked.
func (c *checklist) denyPath() {
	c.fresh("control")
	db := c.fresh("allow")
	azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json", "-send-state-changing")
	settle()
	before := c.site.count("/logout") + c.site.count("/admin")
	db = c.fresh("deny")
	r := azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json", "-send-state-changing", "-deny-path", "^/(logout|admin)")
	settle()
	var probs []string
	if before < 2 {
		probs = append(probs, fmt.Sprintf("without the rule only %d of /logout and /admin/purge were asked: the control proves nothing", before))
	}
	if n := c.site.count("/logout") + c.site.count("/admin"); n > 0 {
		probs = append(probs, fmt.Sprintf("%d requests to a denied path: %v", n, c.site.keys()))
	}
	if !strings.Contains(r.stderr, "-deny-path") {
		probs = append(probs, "the summary does not list what the rule skipped")
	}
	if es := readLedger(db + ".ledger.jsonl"); len(es) == 0 {
		probs = append(probs, "no ledger")
	}
	clCheck("-deny-path keeps /logout and /admin out of every request and the summary says so", probs, "asked without the rule: %d; with it: 0", before)
}

// 3b. A found GET whose own path names a state change is held back by
// default: never asked, listed as skipped with the flag that sends it.
func (c *checklist) heldStateChanging() {
	c.fresh("held-control")
	db := c.fresh("held")
	r := azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json")
	settle()
	var probs []string
	if n := c.site.count("/logout") + c.site.count("/admin/purge"); n > 0 {
		probs = append(probs, fmt.Sprintf("%d requests to a found GET that names a state change: %v", n, c.site.keys()))
	}
	if !strings.Contains(r.stderr, "-send-state-changing") || !strings.Contains(r.stderr, `"state_changing_held"`) {
		probs = append(probs, "the summary does not list the held GETs and the flag that sends them")
	}
	clCheck("a found logout or purge GET is not asked by default and the summary lists it as held back", probs, "asked: %d", c.site.count("/logout")+c.site.count("/admin/purge"))
}

// 4. Nothing leaves the scope, and a target outside it is refused.
func (c *checklist) scope() {
	db := c.fresh("scope")
	azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json", "-dirs", c.file("params.txt"), "-graphql")
	settle()
	var probs []string
	if n := c.site.trapHits.Load(); n > 0 {
		probs = append(probs, fmt.Sprintf("%d requests to the host outside the scope (a link, with -dirs and -graphql on)", n))
	}
	clCheck("scope: no request goes to a host outside it, active modules on", probs, "the page links 127.0.0.2; it was asked %d times", c.site.trapHits.Load())
	c.site.reset()
	db = c.fresh("outside")
	r := azExec(c.dir, 5*time.Minute, "run", "-url", c.site.trap+"/", "-db", db, "-allow", strings.TrimPrefix(c.site.origin, "http://"), "-json")
	settle()
	probs = nil
	if r.exit != 2 {
		probs = append(probs, fmt.Sprintf("exit %d for a target outside the scope, want 2", r.exit))
	}
	if n := c.site.trapHits.Load(); n > 0 {
		probs = append(probs, fmt.Sprintf("the target outside the scope was asked %d times", n))
	}
	clCheck("scope: a target outside -allow is refused with exit 2 and not asked", probs, "exit %d: %s", r.exit, clip(lastLine(r.stderr), 120))
}

// 5. A session that ends is never gone on with as an anonymous run.
func (c *checklist) lostSession() {
	db := c.fresh("session")
	r := azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json", "-cookie", clHasCookie, "-send-state-changing")
	settle()
	c.site.mu.Lock()
	ended := c.site.revokedAt
	c.site.mu.Unlock()
	var probs []string
	if ended.IsZero() {
		probs = append(probs, "the session was never ended: /logout was not asked, the case proves nothing")
	}
	if r.exit != 3 {
		probs = append(probs, fmt.Sprintf("exit %d, want 3 (the run lost its session)", r.exit))
	}
	if !strings.Contains(r.stderr, "the session ended") {
		probs = append(probs, "the summary does not say the session ended")
	}
	var anon []string
	for _, q := range c.site.seen() {
		if !q.Cookie && q.At.After(ended) && !strings.HasPrefix(q.Target, "/me") && !strings.HasPrefix(q.Target, "/login") {
			anon = append(anon, q.key())
		}
	}
	if len(anon) > 0 {
		probs = append(probs, fmt.Sprintf("%d requests went on without the session after it ended: %v", len(anon), anon[:min(len(anon), 5)]))
	}
	clCheck("a lost session (-cookie, so it cannot be renewed) stops the run with exit 3 and never goes on as an anonymous visitor", probs, "exit %d; %s", r.exit, clip(lastLine(r.stderr), 140))
}

// 6. Exit codes mean what OUTPUT.md says.
func (c *checklist) exitCodes() {
	closed := fmt.Sprintf("http://127.0.0.1:%d/", freePorts(1)[0])
	type exitCase struct {
		name string
		want int
		args []string
	}
	db := c.fresh("exit")
	for _, k := range []exitCase{
		{"a target that does not answer", 3, []string{"run", "-url", closed, "-db", db + "a", "-json"}},
		{"one target that answers and one that does not (the run did its job)", 0, []string{"run", "-url", c.site.origin + "/", "-url", closed, "-db", db + "c", "-json"}},
		{"the same with -strict-exit", 3, []string{"run", "-url", c.site.origin + "/", "-url", closed, "-db", db + "d", "-json", "-strict-exit"}},
		{"an unknown flag", 2, []string{"run", "-no-such-flag"}},
		{"a request budget that cuts the run short", 4, []string{"run", "-url", c.site.origin + "/", "-db", db + "b", "-json", "-max-requests", "4"}},
	} {
		c.site.reset()
		r := azExec(c.dir, 5*time.Minute, k.args...)
		settle()
		var probs []string
		if r.exit != k.want {
			probs = append(probs, fmt.Sprintf("exit %d, want %d: %s", r.exit, k.want, clip(lastLine(r.stderr), 100)))
		}
		if k.want == 4 {
			if n := len(c.site.keys()); n > 4 {
				probs = append(probs, fmt.Sprintf("%d requests arrived under a budget of 4", n))
			}
		}
		clCheck("exit code: "+k.name+" is "+fmt.Sprint(k.want), probs, "exit %d", r.exit)
	}
}

// 7. Web and API: crawl, JavaScript routes, API description, GraphQL, paths, parameters.
func (c *checklist) webAndAPI() {
	db := c.fresh("web")
	azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json", "-graphql")
	settle()
	urls := lines(must1(exec.Command(azhaq, "export", "-db", db, "-format", "urls").Output()))
	have := map[string]bool{}
	for _, u := range urls {
		have[strings.TrimPrefix(u, c.site.origin)] = true
	}
	var probs []string
	for _, p := range []string{"/about", "/app.js", "/openapi.json", "/api/items", "/api/items/{id}", "/graphql"} {
		if !have[p] {
			probs = append(probs, "the map lacks "+p)
		}
	}
	clCheck("web and API: the crawl, the script's routes, the API description and the GraphQL endpoint are in the map", probs, "%d URLs in the export", len(urls))
	out, _ := exec.Command(azhaq, "export", "-db", db, "-format", "graphql").Output()
	var probsG []string
	if !strings.Contains(string(out), `"__schema"`) || !strings.Contains(string(out), "Query") {
		probsG = append(probsG, "export -format graphql holds no schema: "+clip(string(out), 100))
	}
	clCheck("web and API: -graphql reads the schema and export gives it back", probsG, "%d bytes", len(out))

	// Paths: the real ones, none of the nonexistent, with a filter.
	words := c.file("words.txt")
	must(os.WriteFile(words, []byte("admin\napi\nlogin\nstatic\nrobots.txt\nfoo\nbar\nbaz\nnope\n"), 0o644))
	c.site.reset()
	res := azExec(c.dir, 5*time.Minute, "dirs", "-u", c.site.origin+"/", "-w", words, "-fc", "404", "-silent")
	got := map[string]bool{}
	for _, l := range lines([]byte(res.stdout)) {
		got[strings.TrimPrefix(firstField(l), c.site.origin)] = true
	}
	var probsD []string
	for _, p := range []string{"/admin", "/api", "/login", "/static", "/robots.txt"} {
		if !got[p] {
			probsD = append(probsD, "missed "+p)
		}
	}
	for p := range got {
		if p == "/foo" || p == "/bar" || p == "/baz" || p == "/nope" {
			probsD = append(probsD, "reported a path that does not exist: "+p)
		}
	}
	clCheck("web and API: dirs finds the five real paths of nine and none of the four that do not exist", probsD, "found %d; exit %d", len(got), res.exit)

	// Parameters: the one that changes the answer.
	pw := c.file("params.txt")
	res = azExec(c.dir, 5*time.Minute, "params", "-u", c.site.origin+"/search", "-w", pw, "-silent")
	var probsP []string
	if !strings.Contains(res.stdout, "debug") {
		probsP = append(probsP, "the parameter that changes the answer (debug) was not found: "+clip(res.stdout, 100))
	}
	for _, n := range []string{"q", "id"} {
		if strings.Contains(res.stdout, n+"=") || strings.Contains(res.stdout, " "+n+"\n") {
			probsP = append(probsP, "reported a parameter the page ignores: "+n)
		}
	}
	clCheck("web and API: params finds the parameter the page reads and not the two it ignores", probsP, "%s", clip(strings.TrimSpace(res.stdout), 100))
}

// 8. Roles: write replay goes only with -replay-writes, only the methods named, and what arrives is what the ledger and the summary say.
func (c *checklist) rolesAndWrites() {
	entry := func(method, path string) map[string]any {
		e := map[string]any{"startedDateTime": "2026-01-01T00:00:00Z", "time": 1,
			"request": map[string]any{"method": method, "url": c.site.origin + path, "httpVersion": "HTTP/1.1", "cookies": []any{}, "queryString": []any{}, "headersSize": -1, "bodySize": 0,
				"headers": []map[string]string{{"name": "Authorization", "value": "Bearer x"}}},
			"response": map[string]any{"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": []any{}, "cookies": []any{}, "headersSize": -1, "bodySize": 0, "content": map[string]any{"size": 2, "mimeType": "application/json", "text": "{}"}},
			"cache":    map[string]any{}, "timings": map[string]any{"send": 0, "wait": 1, "receive": 0}}
		if method != "GET" {
			e["request"].(map[string]any)["postData"] = map[string]any{"mimeType": "application/json", "text": `{"name":"a"}`}
		}
		return e
	}
	har, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "checklist", "version": "1"},
		"entries": []any{entry("GET", "/api/items/1"), entry("PUT", "/api/items/1"), entry("POST", "/api/items"), entry("DELETE", "/api/items/1")}}})
	harFile := c.file("user.har")
	must(os.WriteFile(harFile, har, 0o644))
	for _, put := range []bool{false, true} {
		c.site.reset()
		dir := c.file(fmt.Sprintf("roles-%v.d", put))
		args := []string{"roles", "-dir", dir, "-jsonl", "-role", "anon", "-har", "user=" + harFile}
		if put {
			args = append(args, "-replay-writes", "put")
		}
		r := azExec(c.dir, 5*time.Minute, args...)
		settle()
		es := readLedger(dir + "/roles.ledger.jsonl")
		t := tally{exit: r.exit, summary: summaryRequests(r.stderr), ledger: ledgerKeys(es, c.site.origin), counter: c.site.keys(), ledgerOf: es, stderr: r.stderr}
		probs := t.problems()
		m := c.site.methods()
		name := "roles: the replay of a HAR is reads only and summary = ledger = what the site saw"
		if put {
			name = "roles -replay-writes put: the HAR's PUT is replayed, its POST and DELETE are not, and the counts agree"
			if m["PUT"] == 0 {
				probs = append(probs, fmt.Sprintf("no PUT arrived; methods %v", m))
			}
			for _, w := range writes(m) {
				if !strings.HasPrefix(w, "PUT ") {
					probs = append(probs, "another write arrived: "+w)
				}
			}
		} else if w := writes(m); len(w) > 0 {
			probs = append(probs, fmt.Sprintf("writes arrived without -replay-writes: %v", w))
		}
		if m["GET"] == 0 {
			probs = append(probs, "no read was replayed: the case proves nothing")
		}
		clCheck(name, probs, "summary %d, ledger %d, site %d; methods %v", t.summary, len(t.ledger), len(t.counter), m)
	}
}

// 9. Hunt, diff, export and ingest on a workspace.
func (c *checklist) outputs() {
	db := c.fresh("out")
	azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db, "-json")
	out, err := exec.Command(azhaq, "hunt", "-db", db, "-json").Output()
	var probs []string
	if err != nil || !strings.Contains(string(out), "/admin") && !strings.Contains(string(out), "/api/items") {
		probs = append(probs, fmt.Sprintf("hunt ranked no route of the app (%v): %s", err, clip(string(out), 100)))
	}
	clCheck("hunt: ranks the mapped routes with their evidence", probs, "%d lines", len(lines(out)))

	var dp []string
	db2 := c.fresh("out2")
	azExec(c.dir, 5*time.Minute, "run", "-url", c.site.origin+"/", "-db", db2, "-json", "-dirs", c.file("words.txt"))
	d, _ := exec.Command(azhaq, "diff", "-a", db, "-b", db2, "-jsonl").Output()
	if !strings.Contains(string(d), "/static") {
		dp = append(dp, "the second run's new path /static is not in the diff: "+clip(string(d), 100))
	}
	same, _ := exec.Command(azhaq, "diff", "-a", db, "-b", db, "-jsonl").Output()
	var sum struct{ Added, Removed, Observations int }
	for _, l := range lines(same) {
		_ = json.Unmarshal([]byte(l), &sum)
	}
	if sum.Added+sum.Removed+sum.Observations > 0 || len(lines(same)) != 1 {
		dp = append(dp, "a workspace differs from itself: "+clip(string(same), 100))
	}
	clCheck("diff: a path found by the second run is reported, and a run does not differ from itself", dp, "%d bytes", len(d))

	var ep []string
	spec, _ := exec.Command(azhaq, "export", "-db", db, "-format", "openapi").Output()
	var o struct {
		Paths map[string]any `json:"paths"`
	}
	if json.Unmarshal(spec, &o) != nil || o.Paths["/api/items"] == nil {
		ep = append(ep, "export -format openapi is not an OpenAPI document with /api/items: "+clip(string(spec), 100))
	}
	clCheck("exports: openapi is valid JSON holding the described and called routes", ep, "%d paths", len(o.Paths))

	var ip []string
	feed := c.file("httpx.jsonl")
	must(os.WriteFile(feed, []byte(`{"url":"http://ingest.example.test/","status_code":200,"title":"fed","host":"198.51.100.7","port":"80"}`+"\n"), 0o644))
	idb := c.fresh("ingest")
	if _, err := exec.Command(azhaq, "ingest", "-db", idb, feed).CombinedOutput(); err != nil {
		ip = append(ip, "ingest: "+err.Error())
	}
	urls, _ := exec.Command(azhaq, "export", "-db", idb, "-format", "urls").Output()
	if !strings.Contains(string(urls), "ingest.example.test") {
		ip = append(ip, "the ingested URL is not in the export: "+clip(string(urls), 100))
	}
	clCheck("ingest: a tool's output joins the workspace and is exported", ip, "%s", clip(strings.TrimSpace(string(urls)), 80))
}

// tierSite is an app whose files and panels are known: two real ones and
// the answers that only look like one (the soft 404, the login redirect, the
// index every unknown path gets, a page that is not the file).
func tierSite() (*httptest.Server, map[string]bool) {
	real := map[string]bool{"/.env": true, "/actuator": true}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=production\nDB_PASSWORD=hunter2hunter2\n")
		case "/actuator":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"_links":{"self":{"href":"/actuator"}}}`)
		case "/admin", "/dashboard":
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
		case "/login":
			fmt.Fprint(w, `<html><title>Sign in</title><form><input type="password" name="p"></form></html>`)
		case "/swagger-ui.html":
			fmt.Fprint(w, `<html><title>Page not found</title></html>`)
		case "/backup":
			fmt.Fprint(w, `<html><title>Backups - Acme</title></html>`)
		default:
			fmt.Fprint(w, `<html><title>Acme</title><body>app</body></html>`)
		}
	})), real
}

// 9b. Findings, identifications and leads are counted apart, and the findings
// tier holds no row the app does not have.
func (c *checklist) tiers() {
	srv, real := tierSite()
	defer srv.Close()
	words := c.file("tier-paths.txt")
	must(os.WriteFile(words, []byte(".env\nconfig\nbackup\nadmin\ndashboard\nactuator\nswagger-ui.html\n.git/HEAD\n"), 0o644))
	db := c.file("tiers.db")
	azExec(c.dir, 5*time.Minute, "run", "-url", srv.URL+"/", "-db", db, "-json", "-depth", "1", "-paths", words, "-no-favicon")
	out, _ := exec.Command(azhaq, "export", "-db", db, "-format", "findings").Output()
	n := map[string]int{}
	found := map[string]bool{}
	var probs []string
	for _, l := range lines(out) {
		var row struct {
			Type string
			URL  string
		}
		if json.Unmarshal([]byte(l), &row) != nil {
			continue
		}
		n[row.Type]++
		if row.Type == "finding" {
			p := strings.TrimPrefix(row.URL, srv.URL)
			found[p] = true
			if !real[p] {
				probs = append(probs, "the findings tier holds a row the app does not have: "+p)
			}
		}
	}
	for p := range real {
		if !found[p] {
			probs = append(probs, "the findings tier lacks the real "+p)
		}
	}
	if n["lead"] == 0 {
		probs = append(probs, "the guesses that only look like something are not listed as leads")
	}
	clCheck("findings: the tiers are counted apart, and the findings tier holds only the app's real files and panels", probs,
		"%d findings, %d identifications, %d leads", n["finding"], n["identification"], n["lead"])
}

// 10. The MCP server's lock: no scope, no start; a locked server holds a call to its scope; unlocked, no port scans.
func (c *checklist) mcpLock() {
	var probs []string
	if err := exec.Command(azhaq, "mcp").Run(); exitOf(err) != 2 {
		probs = append(probs, fmt.Sprintf("azhaq mcp with no -allow or -scope exits %d, want 2", exitOf(err)))
	}
	clCheck("mcp: without -allow or -scope the server does not start (exit 2)", probs, "")

	c.site.reset()
	m := startMCP(c.dir, "-allow", strings.TrimPrefix(c.site.origin, "http://"), "-dir", c.file("mcp-lock.d"))
	m.init()
	id := m.mapCall(c.site.trap+"/", "out")
	res := m.read(id)
	settle()
	m.stop()
	_, text := mcpSummary(res[id])
	probs = nil
	if n := c.site.trapHits.Load(); n > 0 {
		probs = append(probs, fmt.Sprintf("a call for a URL outside -allow sent %d requests", n))
	}
	if !strings.Contains(strings.ToLower(text), "scope") && !strings.Contains(strings.ToLower(text), "allow") {
		probs = append(probs, "its result does not say the URL is outside the scope: "+clip(text, 120))
	}
	clCheck("mcp: a tool call cannot widen the scope fixed at start", probs, "result: %s", clip(text, 100))

	l := startTCP("silent")
	defer l.ln.Close()
	u := startMCP(c.dir, "-unlocked", "-dir", c.file("mcp-unlocked.d"))
	u.init()
	pid := u.write("tools/call", map[string]any{"name": "azhaq_ports", "arguments": map[string]any{"hosts": []string{"127.0.0.1"}, "ports": fmt.Sprint(l.port())}}, false)
	pres := u.read(pid)
	settle()
	u.stop()
	_, ptext := mcpSummary(pres[pid])
	probs = nil
	if n := l.accepts.Load(); n != 0 {
		probs = append(probs, fmt.Sprintf("an unlocked server connected %d times for a port scan", n))
	}
	clCheck("mcp: an unlocked server refuses port scans", probs, "result: %s", clip(ptext, 100))
}

// 11. A service says what it is.
func (c *checklist) services() {
	l := startTCP("ssh")
	defer l.ln.Close()
	r := azExec(c.dir, 5*time.Minute, "ports", "-host", "127.0.0.1", "-p", fmt.Sprint(l.port()), "-json")
	var probs []string
	var row struct {
		Service, Product, Version string
	}
	for _, ln := range lines([]byte(r.stdout)) {
		_ = json.Unmarshal([]byte(ln), &row)
	}
	if row.Service != "ssh" || !strings.Contains(strings.ToLower(row.Product), "openssh") || !strings.HasPrefix(row.Version, "9.6") {
		probs = append(probs, fmt.Sprintf("an OpenSSH 9.6 banner was read as %+v", row))
	}
	clCheck("ports: a service on an unusual port is named by what it says (ssh, OpenSSH 9.6)", probs, "%+v", row)
}
