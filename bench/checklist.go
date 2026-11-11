package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The review checklist (.github/ci/trial/GATE.md, part B) as commands: each
// capability a reviewer is asked to exercise is run against servers whose
// answer is known, and the exit code, the counts, the scope and the safety
// claims are checked without a person in the loop. `go run ./bench
// -checklist` runs the units checklistUnits names: claims cases that count
// what a proxy saw, the DNS lab, the deploy lab and this section, whose
// servers are stand-ins that log what reaches them by method.

// checklistUnits are what -checklist runs, in the bench's unit names.
var checklistUnits = []string{"claims:1", "claims:7", "claims:8", "claims:9", "claims:10", "once:lab", "once:deploy", "once:checklist"}

// checklistCover says, for each capability of GATE.md's checklist, which
// units check it ("" for none) and why not. TestChecklistCoversGateMd keeps
// it in step with GATE.md.
var checklistCover = map[string]string{
	"passive collection":                      "not covered: it needs the public sources, which a commit's check must not depend on",
	"live filtering":                          "once:lab",
	"wildcard handling":                       "once:lab",
	"takeover candidates":                     "once:lab",
	"the coverage estimate":                   "not covered: it needs a passive run",
	"resolution and brute force":              "once:lab",
	"tcp connect scan":                        "claims:7, once:checklist",
	"udp scan":                                "claims:7, once:lab",
	"service and version detection":           "once:checklist (one banner), not the services lab",
	"probing at scale":                        "not covered: the bench's probe unit",
	"crawling":                                "once:checklist",
	"javascript routes":                       "once:checklist",
	"api descriptions":                        "once:checklist",
	"graphql":                                 "once:checklist (introspection sent only with -graphql)",
	"path fuzzing with filters":               "once:checklist",
	"parameter discovery":                     "once:checklist",
	"screenshots":                             "not covered: needs Chrome; claims:3 and 11 do it",
	"archived urls":                           "not covered: needs the archives",
	"sign-in":                                 "once:checklist (a session that ends); claims:4 signs in to DVWA",
	"role comparison (read replay)":           "once:checklist",
	"write replay":                            "once:checklist",
	"the proxy-history matrix (har import)":   "not covered",
	"report generation":                       "not covered",
	"hunt":                                    "once:checklist",
	"watch with a deploy that changes routes": "once:deploy",
	"diff":                                "once:checklist",
	"notifications":                       "not covered: the bench's notify unit",
	"exports":                             "once:checklist",
	"ingest":                              "once:checklist",
	"the mcp server":                      "claims:8, once:checklist",
	"request ledger and its verification": "claims:1, once:checklist",
	"kill switch":                         "claims:10",
	"resume":                              "claims:9, claims:10",
}

// ---- the stand-in site ----

// clSite serves a small application that holds a trap for each unsafe thing
// azhaq could do: links to a logout and a purge, a form, a script and an API
// description that name writes, a GraphQL endpoint, a session that a GET
// ends, and a link to a host outside the scope. It logs each request.
type clSite struct {
	origin, trap string
	srv, trapSrv *http.Server
	trapHits     atomic.Int64
	mu           sync.Mutex
	log          []clReq
	revoked      bool
	revokedAt    time.Time
}

type clReq struct {
	seenReq
	Cookie bool
}

func newCLSite() (*clSite, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tl, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &clSite{origin: "http://" + ln.Addr().String(), trap: "http://" + tl.Addr().String()}
	s.trapSrv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.trapHits.Add(1)
		fmt.Fprint(w, "<html><title>trap</title></html>")
	})}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.serve)}
	go s.trapSrv.Serve(tl)
	go s.srv.Serve(ln)
	return s, nil
}

func (s *clSite) close() { _ = s.srv.Close(); _ = s.trapSrv.Close() }

// reset forgets what was logged and puts the session back.
func (s *clSite) reset() {
	s.mu.Lock()
	s.log, s.revoked = nil, false
	s.mu.Unlock()
	s.trapHits.Store(0)
}

func (s *clSite) seen() []clReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

func (s *clSite) keys() []string {
	var out []string
	for _, r := range s.seen() {
		out = append(out, r.key())
	}
	return out
}

// methods are the methods that reached the site, with their counts.
func (s *clSite) methods() map[string]int {
	m := map[string]int{}
	for _, r := range s.seen() {
		m[r.Method]++
	}
	return m
}

func (s *clSite) count(prefix string) int {
	n := 0
	for _, r := range s.seen() {
		if strings.HasPrefix(r.Target, prefix) {
			n++
		}
	}
	return n
}

const clHasCookie = "sid=good"

func (s *clSite) serve(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("sid")
	s.mu.Lock()
	s.log = append(s.log, clReq{seenReq{r.Method, r.URL.RequestURI(), time.Now(), false}, c != nil})
	revoked := s.revoked
	if r.URL.Path == "/logout" && c != nil && !revoked {
		s.revoked, s.revokedAt = true, time.Now()
	}
	s.mu.Unlock()
	html := func(body string) { fmt.Fprintf(w, "<html><title>checklist</title>%s</html>", body) }
	if c != nil && (revoked || r.URL.Path == "/logout") {
		// A logout, and every answer after it, ends the cookie.
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
		if revoked {
			http.Error(w, "session ended", http.StatusUnauthorized)
			return
		}
	}
	switch r.URL.Path {
	case "/":
		html(fmt.Sprintf(`<a href="/about">about</a> <a href="/me">me</a> <a href="/logout">logout</a> <a href="/admin/purge">purge</a> <a href="%s/x">elsewhere</a>
<form method="post" action="/submit"><input name="q"><input type="submit"></form><script src="/app.js"></script>`, s.trap))
	case "/about", "/logout", "/admin/purge", "/admin", "/login", "/api", "/static", "/me":
		if r.URL.Path == "/me" && c == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		html("ok " + r.URL.Path)
	case "/robots.txt":
		fmt.Fprint(w, "User-agent: *\n")
	case "/app.js":
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `fetch("/api/items",{method:"POST",body:JSON.stringify({name:"a"})});fetch("/api/items/1",{method:"DELETE"});`)
	case "/openapi.json":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/api/items":{"get":{"responses":{"200":{"description":"ok"}}},"post":{"responses":{"200":{"description":"ok"}}}},"/api/items/{id}":{"put":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}},"delete":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}`)
	case "/graphql":
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"ping","args":[],"type":{"kind":"SCALAR","name":"String"}}]}]}}}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"message":"POST only"}]}`)
	case "/search":
		if r.URL.Query().Has("debug") {
			html("debug output with a very different body, longer than the plain one, so a parameter that changes the answer shows")
			return
		}
		html("plain")
	case "/submit":
		html("thanks")
	case "/api/items", "/api/items/1":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	default:
		http.NotFound(w, r)
	}
}

// ---- the checks ----

type checklist struct {
	dir  string
	site *clSite
	n    int
}

func (c *checklist) file(name string) string { return filepath.Join(c.dir, name) }

// fresh is a new database path and the site with an empty log.
func (c *checklist) fresh(name string) (db string) {
	c.n++
	c.site.reset()
	return c.file(fmt.Sprintf("%02d-%s.db", c.n, name))
}

// runTally runs azhaq against the site and returns the three counts of that
// run: the summary's, the ledger's and the site's.
func (c *checklist) runTally(db string, timeout time.Duration, args ...string) (azResult, tally) {
	r := azExec(c.dir, timeout, args...)
	settle()
	es := readLedger(db + ".ledger.jsonl")
	t := tally{exit: r.exit, summary: summaryRequests(r.stderr), ledger: ledgerKeys(es, c.site.origin), counter: c.site.keys(), ledgerOf: es, stderr: r.stderr}
	return r, t
}

func writes(m map[string]int) []string {
	var out []string
	for k, n := range m {
		if k != "GET" && k != "HEAD" && k != "OPTIONS" {
			out = append(out, fmt.Sprintf("%s x%d", k, n))
		}
	}
	sort.Strings(out)
	return out
}

func clCheck(name string, problems []string, detail string, a ...any) {
	if len(problems) > 0 {
		detail += " | " + strings.Join(problems, " | ")
	}
	addCheck("checklist: "+name, len(problems) == 0, detail, a...)
}

func benchChecklist() {
	site, err := newCLSite()
	if err != nil {
		addCheck("checklist: the stand-in site starts", false, "%v", err)
		return
	}
	defer site.close()
	dir, _ := filepath.Abs(filepath.Join(work, "checklist"))
	must(os.MkdirAll(dir, 0o755))
	c := &checklist{dir: dir, site: site}
	for _, step := range []func(){c.mapAndCounts, c.writesOnlyWithFlags, c.denyPath, c.heldStateChanging, c.scope, c.lostSession, c.exitCodes,
		c.webAndAPI, c.rolesAndWrites, c.outputs, c.tiers, c.mcpLock, c.services} {
		step()
	}
	logf("checklist coverage:\n%s", checklistTable())
}

// checklistTable is the coverage of GATE.md's checklist, one line each.
func checklistTable() string {
	var keys []string
	for k := range checklistCover {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-42s %s\n", k, checklistCover[k])
	}
	return b.String()
}

// gateCapabilities reads the capabilities of GATE.md's checklist (the
// comma-separated items after each bold area name).
func gateCapabilities(md string) []string {
	var out []string
	in := false
	area := regexp.MustCompile(`^\s*- \*\*[^*]+:\*\* (.+?)\.?$`)
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "- Checklist:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if strings.TrimSpace(l) == "" {
			break
		}
		if m := area.FindStringSubmatch(l); m != nil {
			for _, it := range strings.Split(m[1], ",") {
				it = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(it), "and "))
				if it != "" {
					out = append(out, strings.ToLower(strings.ReplaceAll(it, "`", "")))
				}
			}
		}
	}
	return out
}
