package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// askedSite is a server that records every path it is asked, in order, and
// answers what its pages say.
type askedSite struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newAskedSite(t *testing.T, pages map[string]string, types map[string]string) *askedSite {
	t.Helper()
	s := &askedSite{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.RequestURI())
		s.mu.Unlock()
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		ct := types[r.URL.Path]
		if ct == "" {
			switch {
			case strings.HasSuffix(r.URL.Path, ".js"):
				ct = "application/javascript"
			case strings.HasSuffix(r.URL.Path, ".json"):
				ct = "application/json"
			case strings.HasSuffix(r.URL.Path, ".txt"):
				ct = "text/plain"
			case strings.HasSuffix(r.URL.Path, ".xml"):
				ct = "application/xml"
			default:
				ct = "text/html"
			}
		}
		w.Header().Set("Content-Type", ct)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

// asked is the paths asked, without their queries and without the control's
// requests for a path that cannot exist, as a set.
func (s *askedSite) asked() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for _, p := range s.paths {
		if strings.HasSuffix(strings.SplitN(p, "?", 2)[0], fetch.ProbeToken()) {
			continue
		}
		out[strings.SplitN(p, "?", 2)[0]] = true
	}
	return out
}

func (s *askedSite) reset() {
	s.mu.Lock()
	s.paths = nil
	s.mu.Unlock()
}

// Every URL a link, a script, a GET form or an API description gives is
// requested under any name that declares no state change, and a GET operation
// of a description that needs a path parameter or a required query parameter
// is not; one whose own path or operation declares a state change (a link
// /logout, a script's /api/delete-everything, a form's /reset-all, an
// operation GET /createdb) is held back: not asked, listed as skipped with
// the flag that sends it, and asked with -send-state-changing. An endpoint
// that resets data under another name (/api/flush-all) is asked like any
// other; -deny-path keeps a URL out.
func TestCrawlAsksEveryURLButHoldsTheOnesThatDeclareAStateChange(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body><a href="/logout">out</a><a href="/openapi.json">spec</a><script src="/app.js"></script>
<form action="/reset-all" method="get"><input name="confirm" value="yes"></form>
<form action="/lookup" method="get"><input name="q" type="text"></form></body></html>`,
		"/app.js":                `fetch("/api/delete-everything"); fetch("/api/flush-all");`,
		"/logout":                "bye",
		"/reset-all":             "reset",
		"/lookup":                "found",
		"/api/delete-everything": "gone",
		"/api/flush-all":         "flushed",
		"/createdb":              "made",
		"/openapi.json": `{"openapi":"3.0.1","info":{"title":"t","version":"1"},"paths":{
"/createdb":{"get":{}},
"/spec/free":{"get":{}},
"/spec/item/{id}":{"get":{}},
"/spec/search":{"get":{"parameters":[{"name":"q","in":"query","required":true}]}},
"/spec/optional":{"get":{"parameters":[{"name":"q","in":"query","required":false}]}}}}`,
		"/spec/free": "x", "/spec/optional": "x",
	}
	held := []string{"/logout", "/reset-all", "/api/delete-everything", "/createdb"}
	srv := newAskedSite(t, pages, nil)
	_, errOut := crawlOut(t, srv.httptestServer(), "-silent", "-json")
	got := srv.asked()
	for _, p := range []string{"/api/flush-all", "/lookup", "/spec/free", "/spec/optional", "/openapi.json", "/app.js"} {
		if !got[p] {
			t.Errorf("%s declares nothing and was not asked: %v", p, got)
		}
	}
	for _, p := range []string{"/spec/search", "/spec/item/{id}", "/spec/item/%7Bid%7D"} {
		if got[p] {
			t.Errorf("%s was asked: it needs a parameter", p)
		}
	}
	rep := lastReport(t, errOut)
	for _, p := range held {
		if got[p] {
			t.Errorf("%s declares a state change and was asked", p)
		}
		listed := false
		for _, s := range rep.Skipped {
			if urlPath(s.Target) == p && strings.Contains(s.Reason, "-send-state-changing") {
				listed = true
			}
		}
		if !listed {
			t.Errorf("%s is not listed as skipped with the flag: %+v", p, rep.Skipped)
		}
	}
	if rep.StateChangingHeld != len(held) {
		t.Errorf("state_changing_held %d, want %d", rep.StateChangingHeld, len(held))
	}

	srv.reset()
	crawlOut(t, srv.httptestServer(), "-silent", "-send-state-changing")
	got = srv.asked()
	for _, p := range held {
		if !got[p] {
			t.Errorf("-send-state-changing: %s was not asked: %v", p, got)
		}
	}

	srv.reset()
	_, errOut = crawlOut(t, srv.httptestServer(), "-silent", "-json", "-deny-path", "^/(api/flush-all|lookup)$")
	got = srv.asked()
	if got["/api/flush-all"] || got["/lookup"] {
		t.Errorf("with -deny-path: asked %v", got)
	}
	rep = lastReport(t, errOut)
	denied := 0
	for _, s := range rep.Skipped {
		if strings.Contains(s.Reason, "-deny-path") {
			denied++
		}
	}
	if denied != 2 {
		t.Errorf("-deny-path: %d URLs listed under the rule, want 2: %+v", denied, rep.Skipped)
	}
}

func (s *askedSite) httptestServer() *httptest.Server { return s.Server }

// A crawl asks only what a crawler does: none of run's built-in paths without
// -builtin-paths, which asks them; -kf asks each web service only for its robots.txt
// and sitemaps, and reads every entry.
func TestCrawlAsksOnlyWhatACrawlerDoesAndKFAsksTheKnownFiles(t *testing.T) {
	pages := map[string]string{
		"/":             `<html><body><a href="/about">about</a></body></html>`,
		"/about":        "about",
		"/robots.txt":   "User-agent: *\nDisallow: /hidden\nDisallow: /private/\n",
		"/hidden":       "h",
		"/private/":     "p",
		"/sitemap.xml":  `<?xml version="1.0"?><urlset><url><loc>http://SELF/from-sitemap</loc></url></urlset>`,
		"/from-sitemap": "s",
		"/.git/HEAD":    "ref: refs/heads/main",
		"/admin":        "admin",
		"/swagger.json": `{"swagger":"2.0","paths":{}}`,
	}
	srv := newAskedSite(t, pages, nil)
	pages["/sitemap.xml"] = strings.ReplaceAll(pages["/sitemap.xml"], "SELF", strings.TrimPrefix(srv.URL, "http://"))
	builtIn := []string{"/.git/HEAD", "/admin", "/swagger.json", "/robots.txt", "/sitemap.xml"}
	crawlOut(t, srv.Server, "-silent")
	got := srv.asked()
	for _, p := range builtIn {
		if got[p] {
			t.Errorf("a plain crawl asked %s", p)
		}
	}
	srv.reset()
	crawlOut(t, srv.Server, "-silent", "-builtin-paths")
	got = srv.asked()
	if !got["/.git/HEAD"] || !got["/robots.txt"] || !got["/admin"] {
		t.Errorf("-builtin-paths asked %v", got)
	}
	for _, tc := range []struct {
		kf         string
		want, deny []string
	}{
		{"robotstxt", []string{"/robots.txt", "/hidden", "/private/"}, []string{"/sitemap.xml", "/from-sitemap"}},
		{"sitemapxml", []string{"/sitemap.xml", "/from-sitemap"}, []string{"/robots.txt", "/hidden"}},
		{"all", []string{"/robots.txt", "/hidden", "/private/", "/sitemap.xml", "/from-sitemap"}, nil},
	} {
		srv.reset()
		crawlOut(t, srv.Server, "-silent", "-kf", tc.kf)
		got = srv.asked()
		for _, p := range tc.want {
			if !got[p] {
				t.Errorf("-kf %s did not ask %s: %v", tc.kf, p, got)
			}
		}
		for _, p := range append(tc.deny, "/.git/HEAD", "/admin", "/swagger.json") {
			if got[p] {
				t.Errorf("-kf %s asked %s", tc.kf, p)
			}
		}
	}
}

// With -builtin-paths the catch-all control is asked in every directory, up to 24 an
// origin; a crawl asks it at the root and in the top-level directories only.
func TestCrawlSweepAsksTheControlInAtMost24Directories(t *testing.T) {
	var calls strings.Builder
	pages := map[string]string{"/": `<html><script src="/main.js"></script></html>`}
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&calls, "fetch('/top/d%02d/thing');", i)
		pages[fmt.Sprintf("/top/d%02d/thing", i)] = "x"
	}
	pages["/main.js"] = calls.String()
	srv := newAskedSite(t, pages, nil)
	probes := func() int {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		n := 0
		for _, p := range srv.paths {
			if strings.HasSuffix(p, fetch.ProbeToken()) {
				n++
			}
		}
		return n
	}
	crawlOut(t, srv.Server, "-silent", "-d", "1")
	shallow := probes()
	srv.reset()
	crawlOut(t, srv.Server, "-silent", "-d", "1", "-builtin-paths")
	deep := probes()
	if shallow > 3 || deep <= shallow {
		t.Fatalf("%d control requests by default (the root and /top/) and %d with -builtin-paths", shallow, deep)
	}
	if deep > 24+1 {
		t.Errorf("-builtin-paths asked the control %d times for one origin, want at most 24 (and the root)", deep)
	}
}

// Each distinct URL is listed once: a link written twice, with a fragment or
// from two pages, is one line and one row.
func TestCrawlListsEachDistinctURLOnce(t *testing.T) {
	pages := map[string]string{
		"/":      `<html><a href="/about">1</a><a href="/about">2</a><a href="/about#team">3</a><a href="/other">o</a></html>`,
		"/about": `<html><a href="/other">again</a><a href="/about">self</a></html>`,
		"/other": "o",
	}
	srv := newAskedSite(t, pages, nil)
	out, _ := crawlOut(t, srv.Server, "-silent")
	seen := map[string]int{}
	for _, l := range lines(out) {
		seen[l]++
	}
	for l, n := range seen {
		if n != 1 {
			t.Errorf("%s is listed %d times", l, n)
		}
	}
	if len(seen) != 3 {
		t.Errorf("listed %v, want /, /about and /other", seen)
	}
	jout, _ := crawlOut(t, srv.Server, "-json")
	rows := map[string]int{}
	for _, r := range jsonRows(t, jout) {
		rows[fmt.Sprint(r["url"])]++
	}
	for u, n := range rows {
		if n != 1 {
			t.Errorf("-json has %d rows for %s", n, u)
		}
	}
}

// A crawl never drops a link without a word: every link a page holds is a line
// of the list, or counted in a note of the summary that names what became of
// it.
func TestCrawlAccountsForEveryLinkItDoesNotList(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body><a href="/ok">ok</a><a href="/gone">gone</a><a href="/logo.png">png</a><a href="/doc.pdf">pdf</a>
<a href="http://other.example.org/x">out</a><a href="/secret/page">denied</a></body></html>`,
		"/ok": "ok", "/secret/page": "s", "/doc.pdf": "pdf",
	}
	srv := newAskedSite(t, pages, nil)
	listed, errOut := crawlOut(t, srv.Server, "-deny-path", "^/secret")
	got := map[string]bool{}
	for _, l := range lines(listed) {
		got[strings.TrimPrefix(l, srv.URL)] = true
	}
	note := func(re string) int {
		m := regexp.MustCompile(re).FindStringSubmatch(errOut)
		if m == nil {
			t.Errorf("the summary has no note like %q:\n%s", re, errOut)
			return 0
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	folded := note(`folded not-found: (\d+) URLs? answered 404 or 410`)
	extension := note(`(\d+) rows? (?:was|were) left out of the list by the default extension list`)
	outside := note(`(\d+) links found outside the crawl's scope were not followed`)
	// With -silent the summary is not printed: the notes of the list still are, and the one on
	// links outside the scope is not among them.
	_, silent := crawlOut(t, srv.Server, "-silent", "-deny-path", "^/secret")
	if !strings.Contains(silent, "URL answered 404 or 410") || strings.Contains(silent, "outside the crawl's scope") {
		t.Errorf("-silent says %q", silent)
	}
	// the page's six links: /ok and /secret/page are lines (the second one linked), /gone is folded,
	// /logo.png and /doc.pdf are left out by the extension list, the link to another host is outside the scope.
	if !got["/ok"] || !got["/secret/page"] || folded != 1 || extension != 2 || outside != 1 || (len(got)-1)+folded+extension+outside != 6 {
		t.Errorf("listed %v, folded %d, left out by the extension list %d, outside the scope %d: the six links are not all accounted for\n%s", got, folded, extension, outside, errOut)
	}
}

// Neither crawl nor run caps the tasks it starts unless -max-items says so;
// when a limit (-max-items, -max-requests, -mdp or -timeout) stops the crawl it
// exits 4 and azhaq resume continues it.
func TestCrawlIsNotCappedAndEveryLimitStopsItWithExit4ThenResumeContinues(t *testing.T) {
	var links strings.Builder
	pages := map[string]string{}
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&links, `<a href="/p%03d">p</a>`, i)
		pages[fmt.Sprintf("/p%03d", i)] = fmt.Sprintf("page %d", i)
	}
	pages["/"] = "<html>" + links.String() + "</html>"
	for _, tc := range []struct {
		name    string
		flags   []string
		resume  []string // what lifts the limit on the resume
		stopped string
		slow    bool
	}{
		{"none", nil, nil, "", false},
		{"-max-items", []string{"-max-items", "40"}, []string{"-max-items", "0"}, "-max-items 40", false},
		{"-max-requests", []string{"-max-requests", "30"}, nil, "the request budget of 30", false},
		{"-mdp", []string{"-mdp", "30"}, nil, "", false},
		{"-timeout", []string{"-timeout", "1s"}, []string{"-timeout", "0"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAskedSite(t, pages, nil)
			if tc.slow {
				inner := srv.Server.Config.Handler
				srv.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(150 * time.Millisecond)
					inner.ServeHTTP(w, r)
				})
			}
			db := filepath.Join(t.TempDir(), "w.db")
			_, errOut, err := captureBoth(t, func() error {
				return cmdCrawl(append([]string{"-u", srv.URL + "/", "-allow", "127.0.0.1", "-db", db, "-json"}, tc.flags...))
			})
			first := len(srv.asked())
			if tc.name == "none" {
				if exitCode(err) != exitOK || first != 151 {
					t.Errorf("no limit: exit %d, %d paths asked, want all 151", exitCode(err), first)
				}
				return
			}
			sum := sumMap(t, errOut)
			if exitCode(err) != exitLimit || first >= 151 || !strings.Contains(fmt.Sprint(sum["stopped"]), tc.stopped) {
				t.Fatalf("exit %d after %d paths, stopped %v", exitCode(err), first, sum["stopped"])
			}
			for i := 0; i < 12; i++ {
				_, errOut, err = captureBoth(t, func() error { return run(append([]string{"resume", "-db", db, "-json"}, tc.resume...)) })
				if exitCode(err) == exitOK {
					break
				}
				if exitCode(err) != exitLimit {
					t.Fatalf("resume: %v\n%s", err, errOut)
				}
			}
			if after := len(srv.asked()); after != 151 || exitCode(err) != exitOK {
				t.Errorf("resume: %d paths asked of 151 (%d before), exit %d", after, first, exitCode(err))
			}
		})
	}
}

// Every row has a class (observed, linked, hint or named), and -json prints
// it; views and sockets are hint rows, listed with -json -hints only.
func TestCrawlEveryRowHasAClassAndViewsAreHints(t *testing.T) {
	pages := map[string]string{
		"/": `<html><body><a href="/about">about</a><a href="/missing">m</a><script src="/app.js"></script></body></html>`,
		"/app.js": `var routes=[{path:'dashboard',component:Dash,canActivate:[Guard]}];
fetch("/rest/items/" + id); fetch("/snippets/fixes", {method: "POST", body: "x"}); var m = "/only/named/here";`,
		"/about": "about",
	}
	srv := newAskedSite(t, pages, nil)
	out, _ := crawlOut(t, srv.Server, "-json", "-hints")
	var views []string
	classes := map[string]bool{}
	for _, r := range jsonRows(t, out) {
		c, _ := r["class"].(string)
		if c != "observed" && c != "linked" && c != "hint" && c != "named" {
			t.Errorf("row %v has class %q", r["url"], c)
		}
		classes[c] = true
		if r["role"] == "client-route" || r["role"] == "websocket" {
			views = append(views, fmt.Sprint(r["url"]))
			if c != "hint" {
				t.Errorf("a view or a socket is class %q: %v", c, r)
			}
		}
	}
	if len(views) == 0 || !classes["observed"] || !classes["hint"] || !classes["named"] {
		t.Errorf("classes %v, views %v: the site holds each kind", classes, views)
	}
	plain, _ := crawlOut(t, srv.Server, "-silent", "-hints")
	jsonNoHints, _ := crawlOut(t, srv.Server, "-json")
	for _, v := range views {
		if strings.Contains(jsonNoHints, v) {
			t.Errorf("-json lists the view %s without -hints", v)
		}
		if strings.Contains(plain, v+"\n") {
			t.Errorf("plain -hints output lists the view %s", v)
		}
	}
	for _, r := range jsonRows(t, jsonNoHints) {
		if c := r["class"]; c == "hint" || c == "named" {
			t.Errorf("-json without -hints lists a %v row: %v", c, r["url"])
		}
	}
}

// A page that holds hundreds of script strings does not bury the URLs the
// crawl saw: those strings are named rows that wait for -hints, each with the
// proof that a GET failed and the script only names it.
func TestCrawlKeepsHundredsOfScriptStringsApartAndNamesTheirProof(t *testing.T) {
	var js strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&js, `var s%d = "/named/route%03d";`, i, i)
	}
	pages := map[string]string{
		"/": `<html><a href="/about">about</a><script src="/app.js"></script></html>`, "/about": "about", "/app.js": js.String(),
	}
	srv := newAskedSite(t, pages, nil)
	out, errOut := crawlOut(t, srv.Server, "-silent")
	if n := len(lines(out)); n != 3 {
		t.Errorf("the default list holds %d lines, want the 3 URLs the crawl saw:\n%s", n, out)
	}
	if !strings.Contains(errOut, "300 named URLs were left out of the list (-hints lists them") {
		t.Errorf("no word on the named strings:\n%s", errOut)
	}
	// With -hints the summary says where to look: the strings only scripts name.
	if _, errOut := crawlOut(t, srv.Server, "-hints"); !strings.Contains(errOut, "300 listed URLs are named only in scripts, with no call to say how they are used, and a GET answers 404") {
		t.Errorf("-hints: no note on the named strings:\n%s", errOut)
	}
	// -mr keeps the output small: the pipe a test reads stdout from holds 64 KiB.
	jout, jerr := crawlOut(t, srv.Server, "-json", "-hints", "-mr", `route00\d$`)
	named := 0
	for _, r := range jsonRows(t, jout) {
		if r["class"] == "named" {
			named++
			if r["proof"] != "GET answers 404; found only in scripts, method unknown" {
				t.Errorf("a named row's proof is %q", r["proof"])
			}
		}
	}
	if counts, _ := sumMap(t, jerr)["counts"].(map[string]any); named != 10 || counts["named strings"] != float64(300) {
		t.Errorf("%d named rows printed, counts %v: want the 10 the filter keeps and 300 named strings", named, counts)
	}
}

// The images, fonts and media that -assets, -ndef or -em ask for are listed
// as linked rows, requested or not; the extension list leaves them out of the
// default list, and out of -json too, while .pdf and .txt are rows of -json.
func TestCrawlAssetsAreLinkedRowsAndJSONIsNotCutByTheExtensionListForPages(t *testing.T) {
	pages := map[string]string{
		"/":         `<html><a href="/logo.png">i</a><a href="/doc.pdf">p</a><a href="/notes.txt">t</a><a href="/font.woff2">f</a></html>`,
		"/logo.png": "png", "/doc.pdf": "pdf", "/notes.txt": "txt", "/font.woff2": "font",
	}
	srv := newAskedSite(t, pages, map[string]string{"/logo.png": "image/png", "/doc.pdf": "application/pdf", "/font.woff2": "font/woff2"})
	classes := func(args ...string) map[string]string {
		out, _ := crawlOut(t, srv.Server, append([]string{"-json"}, args...)...)
		m := map[string]string{}
		for _, r := range jsonRows(t, out) {
			m[strings.TrimPrefix(fmt.Sprint(r["url"]), srv.URL)] = fmt.Sprint(r["class"])
		}
		return m
	}
	def := classes()
	if _, ok := def["/logo.png"]; ok || def["/doc.pdf"] == "" || def["/notes.txt"] == "" {
		t.Errorf("-json lists %v: the pdf and the txt are rows, the image is not", def)
	}
	for _, flags := range [][]string{{"-assets"}, {"-ndef"}, {"-em", "png,woff2"}} {
		got := classes(flags...)
		if got["/logo.png"] != "linked" || got["/font.woff2"] != "linked" {
			t.Errorf("%v: the image and the font are %v, want linked rows", flags, got)
		}
	}
	srv.mu.Lock()
	for _, p := range srv.paths {
		if p == "/logo.png" || p == "/font.woff2" {
			t.Errorf("%s was requested", p)
		}
	}
	srv.mu.Unlock()
}

// run's map lists every row, scripts and images included.
func TestRunMapListsScriptsAndImages(t *testing.T) {
	srv := assetsSite(t)
	out, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-allow", "127.0.0.1", "-no-paths", "-no-tech", "-no-favicon", "-sources", "none", "-json", "-db", filepath.Join(t.TempDir(), "w.db")})
	})
	if err != nil && exitCode(err) != exitPartial {
		t.Fatal(err)
	}
	rows := urlRows(t, out)
	for _, p := range []string{"/main.js", "/polyfills.js", "/styles.css", "/logo.png", "/favicon.ico"} {
		if rows[srv.URL+p] == nil {
			t.Errorf("run's map has no row for %s", p)
		}
	}
}

// -json -hints prints every row the extension list and the filters did not
// leave out, and -rejected adds the rejected strings as lines of their own,
// which the number of results counts.
func TestCrawlRejectedStringsAreLinesOfTheirOwnAndCountedInResults(t *testing.T) {
	srv := newAskedSite(t, map[string]string{
		"/":       `<html><a href="/a">a</a><script src="/app.js"></script></html>`,
		"/a":      "a",
		"/app.js": `var d = {"./components/locale/zh_CN": 1}; var e = "/rest/user/" + id; fetch("/x/list");`,
	}, nil)
	_, errOut0 := crawlOut(t, srv.Server, "-json", "-hints")
	plain, _ := crawlOut(t, srv.Server, "-json", "-hints")
	out, errOut := crawlOut(t, srv.Server, "-json", "-hints", "-rejected")
	var rejected, urls int
	for _, r := range jsonRows(t, out) {
		if r["rejected"] != nil {
			rejected++
			if r["reason"] == nil || r["rejected"] == "" {
				t.Errorf("a rejected line without its string or reason: %v", r)
			}
		} else if r["url"] != nil {
			urls++
		}
	}
	if rejected != 2 || urls != len(jsonRows(t, plain)) || sumMap(t, errOut)["results"] != float64(rejected+urls) {
		t.Errorf("%d rejected lines and %d URL rows, results %v (without -rejected: %v)\n%s", rejected, urls, sumMap(t, errOut)["results"], sumMap(t, errOut0)["results"], out)
	}
}

// -em, -ef, -mr and -fr limit what is printed, not what is crawled: the same
// paths are asked with and without them.
func TestCrawlFiltersLimitWhatIsPrintedNotWhatIsCrawled(t *testing.T) {
	pages := map[string]string{
		"/":      `<html><a href="/a.php">a</a><a href="/b.html">b</a><a href="/c.pdf">c</a><a href="/d">d</a></html>`,
		"/a.php": "a", "/b.html": "b", "/c.pdf": "c", "/d": "d",
	}
	srv := newAskedSite(t, pages, nil)
	crawlOut(t, srv.Server, "-silent")
	base := srv.asked()
	for _, flags := range [][]string{{"-em", "php"}, {"-ef", "html"}, {"-mr", "a\\.php"}, {"-fr", "/d$"}} {
		srv.reset()
		out, _ := crawlOut(t, srv.Server, append([]string{"-silent"}, flags...)...)
		if got := srv.asked(); fmt.Sprint(pathSet(got)) != fmt.Sprint(pathSet(base)) {
			t.Errorf("%v: asked %v, want %v", flags, pathSet(got), pathSet(base))
		}
		if len(lines(out)) >= 5 {
			t.Errorf("%v printed %d lines: nothing was left out", flags, len(lines(out)))
		}
	}
}

func pathSet(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -rejected lists the strings kept out of the URLs with a reason, text as the
// string, a tab and the reason, -json with the string, reason, url, source and
// via; none of them is asked.
func TestCrawlRejectedStringsAreNeverAskedAndSayWhy(t *testing.T) {
	pages := map[string]string{
		"/":           `<html><script src="/app.js"></script></html>`,
		"/app.js":     `var d = {"./components/locale/zh_CN": 1}; var e = "/rest/user/" + id; fetch("/x/list"); var f="a\\b/c.php"; var h = "/ok/page.php"; var api = axios.create({baseURL: "/api/v2"}); api.get("/orders/list");`,
		"/robots.txt": "User-agent: *\nDisallow: /*.json$\nDisallow: /secret/*\nDisallow: /hidden\n",
	}
	srv := newAskedSite(t, pages, nil)
	out, _ := crawlOut(t, srv.Server, "-rejected", "-kf", "robotstxt", "-silent")
	reasons := map[string]string{}
	for _, l := range lines(out) {
		if s, why, ok := strings.Cut(l, "\t"); ok {
			reasons[s] = why
		}
	}
	for s, want := range map[string]string{
		"/*.json$":                  "a pattern with a wildcard",
		"/secret/*":                 "a pattern with a wildcard",
		"/rest/user/":               "the start of a path a script joins more to",
		"./components/locale/zh_CN": "a key of a module map or a case label",
		"/orders/list":              "a route a script's client asks under the base",
		`a\\b/c.php`:                "an expression or a template",
	} {
		if !strings.Contains(reasons[s], want) {
			t.Errorf("%q: reason %q, want %q (rejected: %v)", s, reasons[s], want, reasons)
		}
	}
	got := srv.asked()
	for _, p := range []string{"/rest/user/", "/orders/list", "/components/locale/zh_CN", "/*.json$", "/secret/*", "/secret/", "/a%5C%5Cb/c.php", "/a%5C%5C%5Cb/c.php"} {
		if got[p] {
			t.Errorf("the rejected string %s was asked: %v", p, got)
		}
	}
	if !got["/ok/page.php"] || !got["/x/list"] || !got["/hidden"] {
		t.Errorf("what is a URL was not asked: %v", got)
	}
	jout, _ := crawlOut(t, srv.Server, "-rejected", "-json", "-kf", "robotstxt")
	var n int
	for _, r := range jsonRows(t, jout) {
		if r["rejected"] != nil {
			n++
			for _, k := range []string{"rejected", "reason", "source", "via"} {
				if r[k] == nil || r[k] == "" {
					t.Errorf("a rejected line lacks %s: %v", k, r)
				}
			}
		}
	}
	if n < 5 {
		t.Errorf("%d rejected lines in -json", n)
	}
}

// Every form is a forms entry of its page, with method, action, enctype,
// fields and files; a GET form is asked once with neutral values, and
// -no-form-fill and -deny-path keep it from being asked.
func TestCrawlFormsEntriesAndGETFormsAreAskedWithNeutralValues(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	pages := map[string]string{
		"/": `<html><body>
<form action="/search" method="get"><input name="q"><input type="hidden" name="h" value="v"><input type="checkbox" name="c" value="c1" checked><input type="email" name="e"><input type="number" name="n"><select name="s"><option value="o1">1</option><option value="o2" selected>2</option></select></form>
<form action="/up" method="post" enctype="multipart/form-data"><input type="file" name="f"><input name="note"></form>
</body></html>`,
		"/search": "results",
	}
	srv := newAskedSite(t, pages, nil)
	inner := srv.Server.Config.Handler
	srv.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" && r.URL.RawQuery != "" {
			mu.Lock()
			queries = append(queries, r.URL.RawQuery)
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	out, _ := crawlOut(t, srv.Server, "-json")
	var forms []any
	for _, r := range jsonRows(t, out) {
		if r["url"] == srv.URL+"/" {
			forms, _ = r["forms"].([]any)
		}
	}
	if len(forms) != 2 {
		t.Fatalf("forms %v", forms)
	}
	get, _ := forms[0].(map[string]any)
	up, _ := forms[1].(map[string]any)
	if get["method"] != "GET" || get["action"] != srv.URL+"/search" || fmt.Sprint(get["fields"]) != "[q h c e n s]" ||
		up["method"] != "POST" || up["enctype"] != "multipart/form-data" || fmt.Sprint(up["files"]) != "[f]" || fmt.Sprint(up["fields"]) != "[f note]" {
		t.Errorf("the forms entries: %v", forms)
	}
	mu.Lock()
	if len(queries) != 1 {
		t.Fatalf("the GET form was asked %d times: %q", len(queries), queries)
	}
	q, _ := url.ParseQuery(queries[0])
	mu.Unlock()
	want := url.Values{"q": {"azhaq"}, "h": {"v"}, "c": {"c1"}, "e": {"azhaq@example.org"}, "n": {"1"}, "s": {"o2"}}
	if fmt.Sprint(q) != fmt.Sprint(want) {
		t.Errorf("the GET form was asked with %v, want %v", q, want)
	}
	for _, flags := range [][]string{{"-no-form-fill"}, {"-deny-path", "^/search"}} {
		mu.Lock()
		queries = nil
		mu.Unlock()
		crawlOut(t, srv.Server, append([]string{"-silent"}, flags...)...)
		mu.Lock()
		if len(queries) != 0 {
			t.Errorf("%v: the GET form was asked: %q", flags, queries)
		}
		mu.Unlock()
	}
}

// A POST form is sent only with -submit-forms, urlencoded; one that posts to
// its own page (an empty action, or #) is handled like any other; one with
// nothing to send is not sent, and the summary says so.
func TestCrawlSubmitFormsOwnPageAndNothingToSend(t *testing.T) {
	var mu sync.Mutex
	var posts []string
	pages := map[string]string{
		"/page": `<html><body><form action="" method="post"><input name="a"></form><form action="#" method="post"><input name="b"></form>
<form action="/empty" method="post"></form></body></html>`,
	}
	srv := newAskedSite(t, pages, nil)
	inner := srv.Server.Config.Handler
	srv.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			posts = append(posts, r.URL.Path+" "+r.Header.Get("Content-Type")+" "+string(b))
			mu.Unlock()
			return
		}
		inner.ServeHTTP(w, r)
	})
	run := func(extra ...string) (string, string) {
		out, errOut, err := captureBoth(t, func() error {
			return cmdCrawl(append([]string{"-u", srv.URL + "/page", "-allow", "127.0.0.1", "-json", "-db", filepath.Join(t.TempDir(), "w.db")}, extra...))
		})
		if err != nil && exitCode(err) != exitPartial {
			t.Fatal(err)
		}
		return out, errOut
	}
	out, _ := run()
	mu.Lock()
	if len(posts) != 0 {
		t.Errorf("without -submit-forms: %q", posts)
	}
	mu.Unlock()
	var actions []string
	for _, r := range jsonRows(t, out) {
		if r["url"] == srv.URL+"/page" {
			for _, f := range r["forms"].([]any) {
				actions = append(actions, f.(map[string]any)["action"].(string))
			}
		}
	}
	if fmt.Sprint(actions) != fmt.Sprint([]string{srv.URL + "/page", srv.URL + "/page", srv.URL + "/empty"}) {
		t.Errorf("the actions of the forms: %v: an empty action or # is the page's own URL", actions)
	}
	_, errOut := run("-submit-forms")
	sort.Strings(posts)
	if fmt.Sprint(posts) != fmt.Sprint([]string{"/page application/x-www-form-urlencoded a=azhaq", "/page application/x-www-form-urlencoded b=azhaq"}) {
		t.Errorf("posts %q", posts)
	}
	if !strings.Contains(errOut, "/empty was not submitted: it uploads a file or has nothing to send") || !strings.Contains(errOut, "2 POST forms were submitted") {
		t.Errorf("summary:\n%s", errOut)
	}
}

// Library scripts are not read for routes: react, jquery and angular, also
// under a versioned name.
func TestCrawlDoesNotReadReactJQueryAndAngularBuilds(t *testing.T) {
	pages := map[string]string{
		"/":                           `<html><script src="/js/react.production.min.js"></script><script src="/js/jquery-3.7.1.min.js"></script><script src="/js/angular.min.js"></script><script src="/js/angular_1-7-7.js"></script><script src="/js/app.js"></script></html>`,
		"/js/react.production.min.js": `fetch("/lib/react-only");`, "/js/jquery-3.7.1.min.js": `fetch("/lib/jquery-only");`,
		"/js/angular.min.js": `fetch("/lib/angular-only");`, "/js/angular_1-7-7.js": `fetch("/lib/angular-versioned-only");`,
		"/js/app.js": `fetch("/app/route");`,
	}
	srv := newAskedSite(t, pages, nil)
	out, _ := crawlOut(t, srv.Server, "-silent")
	got := srv.asked()
	for _, p := range []string{"/lib/react-only", "/lib/jquery-only", "/lib/angular-only", "/lib/angular-versioned-only"} {
		if got[p] || strings.Contains(out, p) {
			t.Errorf("a string of a library script was taken: %s", p)
		}
	}
	if !got["/app/route"] {
		t.Errorf("the app's script was not read: %v", got)
	}
}

// -jsonl gives a URL that was found and not asked a line with no response.
func TestCrawlJSONLLineOfAURLNotAskedHasNoResponse(t *testing.T) {
	pages := map[string]string{
		"/":  `<html><a href="/a">a</a></html>`,
		"/a": `<html><a href="/b">b</a></html>`,
		"/b": "b",
	}
	srv := newAskedSite(t, pages, nil)
	out, _ := crawlOut(t, srv.Server, "-d", "1", "-jsonl")
	seen := map[string]map[string]any{}
	for _, r := range jsonRows(t, out) {
		req, _ := r["request"].(map[string]any)
		seen[strings.TrimPrefix(fmt.Sprint(req["endpoint"]), srv.URL)] = r
	}
	if seen["/a"] == nil || seen["/a"]["response"] == nil || seen["/b"] == nil || seen["/b"]["response"] != nil {
		t.Errorf("-jsonl lines: %v", seen)
	}
	if srv.asked()["/b"] {
		t.Errorf("/b was asked at -d 1")
	}
}

// -do lists the URLs found outside the crawl's scope and never asks them; in
// -json each is a row with coverage out-of-scope, its source, tag and attribute.
func TestCrawlDoListsTheURLsOutsideTheScopeAndNeverAsksThem(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	third := strings.Replace(other.URL, "127.0.0.1", "localhost", 1) // another site
	pages := map[string]string{"/": `<html><a href="` + third + `/x">out</a><a href="/in">in</a><script src="` + third + `/lib.js"></script></html>`, "/in": "in"}
	srv := newAskedSite(t, pages, nil)
	out, _ := crawlOut(t, srv.Server, "-do", "-silent")
	if !strings.Contains(out, third+"/x\n") {
		t.Errorf("-do does not list the link outside the scope:\n%s", out)
	}
	if strings.Contains(func() string { o, _ := crawlOut(t, srv.Server, "-silent"); return o }(), third) {
		t.Errorf("a plain crawl lists a URL, or a script, outside the scope")
	}
	jout, _ := crawlOut(t, srv.Server, "-do", "-json")
	var row map[string]any
	for _, r := range jsonRows(t, jout) {
		if r["url"] == third+"/x" {
			row = r
		}
	}
	if row == nil || row["coverage"] != "out-of-scope" || row["source"] != srv.URL+"/" || row["tag"] != "a" || row["attribute"] != "href" {
		t.Errorf("the -do row: %v", row)
	}
	if elsewhere.Load() != 0 {
		t.Errorf("%d requests went to the host outside the scope", elsewhere.Load())
	}
}

// -no-catchall leaves the catch-all rows out of every view; a URL a script
// names is not folded when -hints lists it.
func TestCrawlNoCatchallLeavesTheCatchAllRowsOutOfEveryView(t *testing.T) {
	srv, truth := juiceShop(t)
	for _, args := range [][]string{{"-silent", "-all-rows"}, {"-json"}, {"-json", "-all-rows"}} {
		out, _ := crawlOut(t, srv, append(args, "-no-catchall")...)
		for _, p := range truth.shell {
			if strings.Contains(out, srv.URL+p+"\n") || strings.Contains(out, `"url":"`+srv.URL+p+`"`) {
				t.Errorf("%v -no-catchall still lists %s", args, p)
			}
		}
		if !strings.Contains(out, "/rest/products/search") {
			t.Errorf("%v -no-catchall lost a confirmed route:\n%.200s", args, out)
		}
	}
	// without it, -all-rows lists them
	if out, _ := crawlOut(t, srv, "-silent", "-all-rows"); !strings.Contains(out, srv.URL+truth.shell[0]+"\n") {
		t.Errorf("-all-rows does not list %s", truth.shell[0])
	}
}

func TestCrawlANamedURLIsNotFoldedWhenHintsListsIt(t *testing.T) {
	pages := map[string]string{"/": `<html><script src="/app.js"></script></html>`, "/app.js": `var a = "/only/in/scripts";`}
	srv := newAskedSite(t, pages, nil)
	out, errOut := crawlOut(t, srv.Server, "-silent", "-hints")
	if !strings.Contains(out, srv.URL+"/only/in/scripts\n") {
		t.Errorf("-hints does not list the named URL:\n%s", out)
	}
	if strings.Contains(errOut, "folded not-found") {
		t.Errorf("the named URL listed with -hints is folded:\n%s", errOut)
	}
	_, errOut = crawlOut(t, srv.Server, "-silent")
	if !strings.Contains(errOut, "1 named URLs were left out of the list") {
		t.Errorf("without -hints:\n%s", errOut)
	}
}

// A page linked under several spellings that name one resource (an escaped
// letter, a fragment, the default port, the case of the host) is asked once;
// a trailing slash or an empty query is another request.
func TestCrawlAsksAPageOnceWhateverSpellingNamesIt(t *testing.T) {
	pages := map[string]string{
		"/":      "",
		"/about": "about us",
	}
	srv := newAskedSite(t, pages, nil)
	host := strings.TrimPrefix(srv.URL, "http://")
	pages["/"] = `<html><body><a href="/about">1</a><a href="/%61bout">2</a><a href="/about#team">3</a>` +
		`<a href="http://` + strings.ToUpper(host) + `/about">4</a><a href="/about/">5</a><a href="/about?">6</a></body></html>`
	crawlOut(t, srv.httptestServer(), "-silent")
	srv.mu.Lock()
	defer srv.mu.Unlock()
	n := map[string]int{}
	for _, p := range srv.paths {
		n[p]++
	}
	if got := n["/about"] + n["/%61bout"]; got != 1 {
		t.Errorf("/about is one resource under four spellings and was asked %d times (%v)", got, n)
	}
	if n["/about/"] != 1 || n["/about?"] != 1 {
		t.Errorf("a trailing slash and an empty query are other requests: %v", n)
	}
}
