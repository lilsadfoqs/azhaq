package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/browser"
	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// reqLog is a server's log of what it was asked: method, path and the
// credential headers of each request, in order.
type reqLog struct {
	mu   sync.Mutex
	list []loggedReq
}

type loggedReq struct {
	method, path, auth, cookie, role string
}

func (l *reqLog) add(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, loggedReq{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("X-Role")})
}

func (l *reqLog) all() []loggedReq {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.list)
}

// rolesRows runs roles -json and returns its rows by path and its summary.
func rolesRows(t *testing.T, site string, args ...string) (map[string]roleRow, report, error) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return cmdRoles(append([]string{"-json", "-dir", t.TempDir()}, args...)) })
	rows := map[string]roleRow{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var row roleRow
		if json.Unmarshal([]byte(l), &row) != nil {
			t.Fatalf("not a row: %s", l)
		}
		rows[row.Method+" "+strings.TrimPrefix(row.URL, site)] = row
	}
	return rows, lastReport(t, errOut), err
}

// Three accounts each browsed one page of their own: the replay asks every
// page of every other account with each other account's session and the
// anonymous visitor's, GETs only, and nothing else is requested (no crawl
// without run options).
func TestRolesAskEveryEndpointOfEveryOtherRole(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"sign in"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"page":%q,"seen_by":%q}`, r.URL.Path, r.Header.Get("Authorization"))
	}))
	defer site.Close()
	browse := func(file, user string) string {
		return writeHAR(t, file, harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/pages/"+user, "", 200, "Authorization", "Bearer "+user))
	}
	rows, _, err := rolesRows(t, site.URL, "-all", "-har", "alice="+browse("a.har", "alice"), "-har", "bob="+browse("b.har", "bob"), "-har", "carol="+browse("c.har", "carol"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range log.all() {
		if r.method != "GET" || !strings.HasPrefix(r.path, "/pages/") {
			t.Errorf("a request that is no page of a history: %s %s", r.method, r.path)
		}
		got[r.path+" "+r.auth] = true
	}
	for _, page := range []string{"alice", "bob", "carol"} {
		for _, who := range []string{"Bearer alice", "Bearer bob", "Bearer carol", ""} {
			if !got["/pages/"+page+" "+who] {
				t.Errorf("/pages/%s was not asked with %q", page, who)
			}
		}
		row, ok := rows[" /pages/"+page]
		if !ok || len(row.Status) != 4 || row.Status["anon"] != 401 || row.Status["alice"] != 200 || row.Status["bob"] != 200 || row.Status["carol"] != 200 {
			t.Errorf("the row of /pages/%s compares each role's answer: %+v", page, row.Status)
		}
	}
	if len(got) != 12 {
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("%d different requests, want the 12 of 3 pages and 4 roles: %q", len(keys), keys)
	}
}

// A role sends the headers it is given and nothing else: not another
// role's, not a cookie the server set, not the run options' (roles refuses
// -cookie and -header there). A cookie app is not reached by a header.
func TestRolesARoleSendsOnlyTheHeadersItIsGiven(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		http.SetCookie(w, &http.Cookie{Name: "track", Value: "1", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><title>home</title><a href="/about">about</a> <a href="/whoami">me</a></html>`)
		case "/about":
			fmt.Fprint(w, `<html><title>about</title></html>`)
		case "/whoami":
			c, _ := r.Cookie("token")
			w.Header().Set("Content-Type", "application/json")
			if c != nil {
				fmt.Fprintf(w, `{"user":{"name":%q}}`, c.Value)
				return
			}
			fmt.Fprint(w, `{"user":{}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	rows, _, err := rolesRows(t, site.URL, "-all", "-role", "anon", "-role", "alice=X-Role: alice", "-role", "bob=Authorization: Bearer bob",
		"-role", "carol=Authorization: Bearer carol", "-role", "carol=Cookie: token=carol", "--", "-url", site.URL+"/", "-no-paths")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, r := range log.all() {
		kind := "anon"
		switch {
		case r.role != "":
			kind = "alice"
		case r.auth == "Bearer bob":
			kind = "bob"
		case r.auth == "Bearer carol":
			kind = "carol"
		case r.auth != "":
			t.Errorf("an Authorization header nobody was given: %q", r.auth)
		}
		counts[kind]++
		switch kind {
		case "anon":
			if r.cookie != "" {
				t.Errorf("the anonymous role sent a cookie: %q (%s)", r.cookie, r.path)
			}
		case "alice":
			if r.auth != "" || r.cookie != "" || r.role != "alice" {
				t.Errorf("alice sent more or other than X-Role: %+v", r)
			}
		case "bob":
			if r.role != "" || r.cookie != "" {
				t.Errorf("bob sent more than his Authorization: %+v", r)
			}
		case "carol":
			if r.role != "" || r.cookie != "token=carol" {
				t.Errorf("carol sent more or other than her two headers: %+v", r)
			}
		}
	}
	for _, k := range []string{"anon", "alice", "bob", "carol"} {
		if counts[k] == 0 {
			t.Errorf("no request of %s was seen", k)
		}
	}
	// The app reads its session from the cookie: a bearer header alone is a visitor.
	if st := rows[" /whoami"].Status; len(st) != 4 {
		t.Fatalf("/whoami row %+v", rows[" /whoami"])
	}
	who := rows[" /whoami"].Answers
	if who["bob"].Hash != who["anon"].Hash || who["carol"].Hash == who["anon"].Hash {
		t.Errorf("an Authorization header reaches a cookie app as the visitor, a Cookie header as the user: %+v", who)
	}
}

// crawlSite is a small site whose pages link to each other; the log keeps
// what it was asked.
func crawlSite(t *testing.T, log *reqLog, pages int) *httptest.Server {
	t.Helper()
	var links strings.Builder
	for i := 1; i <= pages; i++ {
		fmt.Fprintf(&links, `<a href="/p%d">p%d</a> `, i, i)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			fmt.Fprintf(w, `<html><title>home</title>%s</html>`, links.String())
		case strings.HasPrefix(r.URL.Path, "/p"):
			fmt.Fprintf(w, `<html><title>%s</title>page</html>`, r.URL.Path)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(site.Close)
	return site
}

// -max-requests is the budget of the whole command: each role's run gets
// what the runs before it left, and a run with no budget left does not start.
func TestRolesARunWithNoBudgetLeftDoesNotStart(t *testing.T) {
	var log reqLog
	site := crawlSite(t, &log, 6)
	const budget = 12
	_, rep, err := rolesRows(t, site.URL, "-role", "anon", "-role", "alice=X-Role: alice", "-role", "bob=X-Role: bob",
		"--", "-url", site.URL+"/", "-no-paths", "-max-requests", fmt.Sprint(budget))
	if exitCode(err) != exitLimit {
		t.Errorf("exit %d (%v), want %d", exitCode(err), err, exitLimit)
	}
	per := map[string]int{}
	for _, r := range log.all() {
		switch r.role {
		case "alice":
			per["alice"]++
		case "bob":
			per["bob"]++
		default:
			per["anon"]++
		}
	}
	total := per["anon"] + per["alice"] + per["bob"]
	if total > budget || int64(total) != rep.Requests {
		t.Errorf("the site saw %d requests (%v), the summary says %d, the budget is %d", total, per, rep.Requests, budget)
	}
	// anon's run took part of it; alice's got what was left; bob's was not started.
	if per["anon"] == 0 || per["alice"] == 0 || per["bob"] != 0 {
		t.Errorf("the runs sent %v: each run gets what the ones before it left, the last none", per)
	}
	all := rep.Stopped + "\n" + strings.Join(rep.Notes, "\n")
	if !strings.Contains(all, "was spent before role bob's run: its run did not start") || !strings.Contains(rep.Stopped, "-max-requests 12") {
		t.Errorf("stopped %q, notes %q", rep.Stopped, rep.Notes)
	}
}

// -replay-max limits the history reads over all roles: the roles' histories
// are read in turn, and what is left is what the next role's reads may send.
func TestRolesReplayMaxLimitsTheHistoryReadsOverAllRoles(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer site.Close()
	browse := func(file, user string) string {
		var es []map[string]any
		for i := 1; i <= 3; i++ {
			es = append(es, harEntry(fmt.Sprintf("2026-10-29T10:00:0%d.000Z", i), "GET", fmt.Sprintf("%s/%s/%d", site.URL, user, i), "", 200, "Authorization", "Bearer "+user))
		}
		return writeHAR(t, file, es...)
	}
	_, rep, err := rolesRows(t, site.URL, "-replay-max", "5", "-har", "alice="+browse("a.har", "alice"), "-har", "bob="+browse("b.har", "bob"), "-har", "carol="+browse("c.har", "carol"))
	if exitCode(err) != exitLimit {
		t.Errorf("exit %d (%v), want %d", exitCode(err), err, exitLimit)
	}
	var alice, bob, carol int
	for _, r := range log.all() {
		switch {
		case strings.HasPrefix(r.path, "/alice/") && r.auth == "Bearer alice":
			alice++
		case strings.HasPrefix(r.path, "/bob/") && r.auth == "Bearer bob":
			bob++
		case strings.HasPrefix(r.path, "/carol/") && r.auth == "Bearer carol":
			carol++
		}
	}
	if alice != 3 || bob != 2 || carol != 0 || !strings.Contains(rep.Stopped, "-replay-max") {
		t.Errorf("history reads: alice %d, bob %d, carol %d, stopped %q: the 5 are spent over all roles in turn", alice, bob, carol, rep.Stopped)
	}
}

// The replay takes a URL only while -replay-max holds the request of every
// role that is to be asked it.
func TestRolesReplayTakesAURLOnlyWhileTheBudgetHoldsEveryRole(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		fmt.Fprint(w, `{}`)
	}))
	defer site.Close()
	roles := []role{{name: "alice", session: http.Header{"Authorization": {"alice"}}}, {name: "bob", session: http.Header{"Authorization": {"bob"}}},
		{name: "carol", session: http.Header{"Authorization": {"carol"}}}}
	answers := map[string]map[string]answer{"alice": {}, "bob": {}, "carol": {}}
	found := map[string][]string{}
	for i := 1; i <= 4; i++ {
		u := fmt.Sprintf("%s/o/%d", site.URL, i)
		answers["alice"][u] = answer{Status: 200}
		found[u] = []string{"alice"}
	}
	sent, err := replayAll(roles, answers, found, nil, map[string]bool{"127.0.0.1": true}, 0, 5, nil)
	asked := map[string]map[string]bool{}
	for _, r := range log.all() {
		if asked[r.path] == nil {
			asked[r.path] = map[string]bool{}
		}
		asked[r.path][r.auth] = true
	}
	// Two URLs fit in 5 requests (2 roles each); a third would need 2 more.
	if sent != 4 || len(log.all()) != 4 || len(asked) != 2 {
		t.Errorf("sent %d, the site saw %d requests for %d URLs, want 4 for 2", sent, len(log.all()), len(asked))
	}
	for p, who := range asked {
		if !who["bob"] || !who["carol"] || len(who) != 2 {
			t.Errorf("%s was asked of %v: a URL is taken for every role or for none", p, who)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "2 URLs were not asked of every role") {
		t.Errorf("the URLs left are not named: %v", err)
	}
}

// A role whose only credential is a token that has expired: the run says
// what came of it. A site that refuses it makes a dead session (exit 3); a
// site that still takes it is a finding; with nothing to tell, a note and
// exit 3.
func TestRolesAnExpiredTokenEndsInOneOfThreeWays(t *testing.T) {
	expired := jwt(`{"sub":"alice","exp":1700000000}`)
	app := func(mode string) *httptest.Server {
		site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, `<html><title>home</title><a href="/me">me</a></html>`)
			case r.URL.Path != "/me":
				http.NotFound(w, r)
			case mode == "public":
				fmt.Fprint(w, `{"user":"everyone"}`)
			case mode == "takes" && r.Header.Get("Authorization") != "":
				fmt.Fprint(w, `{"user":"alice"}`)
			default:
				w.WriteHeader(401)
				fmt.Fprint(w, `{"message":"jwt expired"}`)
			}
		}))
		t.Cleanup(site.Close)
		return site
	}
	for _, c := range []struct {
		mode, note string
		exit       int
	}{
		{"refuses", "role alice was refused wherever a session matters", exitPartial},
		{"takes", "role alice's token expired at 2023-11-14T22:13:20Z, yet the site still let it read 1 endpoint the anonymous role is refused: check that it verifies token expiry", exitOK},
		{"public", "role alice's token expired at 2023-11-14T22:13:20Z and nothing it was asked tells whether the site still takes it", exitPartial},
	} {
		site := app(c.mode)
		_, rep, err := rolesRows(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+expired, "--", "-url", site.URL+"/", "-no-paths")
		if exitCode(err) != c.exit || rep.Exit != c.exit {
			t.Errorf("%s: exit %d (%v), summary %d, want %d", c.mode, exitCode(err), err, rep.Exit, c.exit)
		}
		if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.Contains(n, c.note) }) {
			t.Errorf("%s: no note %q in %q", c.mode, c.note, rep.Notes)
		}
		if c.mode == "refuses" && !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.Contains(n, "its token expired at 2023-11-14T22:13:20Z") }) {
			t.Errorf("a dead session with an expired token says so: %q", rep.Notes)
		}
	}
}

// dropFor is a server that drops the connection of a request to path made
// with the credential who, and answers every other request with its path.
func dropFor(t *testing.T, log *reqLog, method, path, who string) *httptest.Server {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Method == method && r.URL.Path == path && r.Header.Get("Authorization") == who {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q,"by":%q}`, r.URL.Path, r.Header.Get("Authorization"))
	}))
	t.Cleanup(site.Close)
	return site
}

// A replay read, a page of a history, a write that gets no answer ends the
// run with exit 3 and a note that says how many and why; a request a
// -deny-path rule keeps out is not one.
func TestRolesAnUnansweredRequestIsExit3ButADeniedOneIsNot(t *testing.T) {
	for _, c := range []struct {
		name, method, path, who string
		args                    []string
		note                    string
	}{
		{"a replay read", "GET", "/a/1", "Bearer bob", nil, "role bob: 1 request of the replay got no answer, so it is missing from the comparison: "},
		{"a page of a history", "GET", "/a/1", "Bearer alice", nil, "role alice: 1 page of its history got no answer, so it is missing from the comparison: "},
		{"a write", "PUT", "/a/1", "Bearer bob", []string{"-replay-writes", "put"}, "write replay: 1 request got no answer, so the rows say what the others showed: "},
	} {
		var log reqLog
		site := dropFor(t, &log, c.method, c.path, c.who)
		har := func(file, user string) string {
			es := []map[string]any{harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/"+user[:1]+"/1", "", 200, "Authorization", "Bearer "+user)}
			if user == "alice" {
				es = append(es, harEntry("2026-10-29T10:00:01.000Z", "PUT", site.URL+"/a/1", `{"note":"x"}`, 200, "Authorization", "Bearer alice", "Content-Type", "application/json"))
			}
			return writeHAR(t, file, es...)
		}
		args := append([]string{"-har", "alice=" + har("a.har", "alice"), "-har", "bob=" + har("b.har", "bob")}, c.args...)
		_, rep, err := rolesRows(t, site.URL, args...)
		if exitCode(err) != exitPartial || rep.Exit != exitPartial {
			t.Errorf("%s: exit %d (%v), want %d; notes %q", c.name, exitCode(err), err, exitPartial, rep.Notes)
		}
		if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.HasPrefix(n, c.note) }) {
			t.Errorf("%s: no note %q in %q", c.name, c.note, rep.Notes)
		}
	}
}

// The same requests, kept out by a -deny-path rule of the user, are no
// failure: the run exits 0.
func TestRolesADeniedRequestIsNotAFailure(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer site.Close()
	har := func(file, user string) string {
		es := []map[string]any{harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/"+user[:1]+"/1", "", 200, "Authorization", "Bearer "+user)}
		if user == "alice" {
			es = append(es, harEntry("2026-10-29T10:00:01.000Z", "PUT", site.URL+"/a/1", `{"note":"x"}`, 200, "Authorization", "Bearer alice", "Content-Type", "application/json"))
		}
		return writeHAR(t, file, es...)
	}
	_, rep, err := rolesRows(t, site.URL, "-har", "alice="+har("a.har", "alice"), "-har", "bob="+har("b.har", "bob"), "-replay-writes", "put",
		"--", "-url", site.URL+"/", "-no-paths", "-deny-path", "^/(a|b)/")
	if err != nil || rep.Exit != exitOK {
		t.Errorf("exit %d (%v), notes %q", rep.Exit, err, rep.Notes)
	}
	for _, r := range log.all() {
		if strings.HasPrefix(r.path, "/a/") || strings.HasPrefix(r.path, "/b/") {
			t.Errorf("a request the rule keeps out was sent: %s %s", r.method, r.path)
		}
	}
}

// A role whose run cannot be done ends roles with a summary whose notes say
// why: a -role-cmd that fails, and a sign-in that fails.
func TestRolesARoleThatCannotRunEndsWithANoteSayingWhy(t *testing.T) {
	var log reqLog
	site := crawlSite(t, &log, 2)
	_, rep, err := rolesRows(t, site.URL, "-role", "anon", "-role-cmd", "bob=exit 7", "--", "-url", site.URL+"/", "-no-paths")
	if exitCode(err) != exitError || rep.Exit != exitError || rep.Complete {
		t.Errorf("a -role-cmd that fails: exit %d (%v), summary %d, notes %q", exitCode(err), err, rep.Exit, rep.Notes)
	}
	if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.Contains(n, "role bob: its -role-cmd failed") }) {
		t.Errorf("the notes do not say why: %q", rep.Notes)
	}
}

func TestRolesAFailedSignInEndsWithANoteSayingWhy(t *testing.T) {
	if _, err := browser.Find(); err != nil {
		t.Skip(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/login.php" && r.Method == http.MethodPost:
			fmt.Fprint(w, `<html><title>Login</title><body>Login failed<form action="login.php" method=post><input name=username><input type=password name=password><input type=submit value=Login></form></body></html>`)
		case r.URL.Path == "/login.php":
			fmt.Fprint(w, `<html><title>Login</title><body><form action="login.php" method=post><input name=username><input type=password name=password><input type=submit value=Login></form></body></html>`)
		default:
			fmt.Fprint(w, `<html><title>home</title><a href="/login.php">sign in</a></html>`)
		}
	}))
	defer site.Close()
	_, rep, err := rolesRows(t, site.URL, "-login", site.URL+"/login.php", "-role", "anon", "-role-login", "admin=admin:wrong",
		"--", "-url", site.URL+"/", "-no-paths", "-depth", "0", "-allow", strings.TrimPrefix(site.URL, "http://"))
	if exitCode(err) != exitError || rep.Exit != exitError || rep.Complete {
		t.Errorf("a sign-in that failed: exit %d (%v), summary %d", exitCode(err), err, rep.Exit)
	}
	if !slices.ContainsFunc(rep.Notes, func(n string) bool {
		return strings.HasPrefix(n, "role admin: -login "+site.URL+"/login.php: the login form is still there after submitting it")
	}) {
		t.Errorf("the notes do not say why: %q", rep.Notes)
	}
}

// requests in the summary is every request roles sent to the targets: the
// runs' and the replay's, a redirect's hops included. A role's own summary
// line counts that role's run only, so they add up to less.
func TestRolesRequestsAreEveryRequestSentAndTheRolesRunsAddUpToLess(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "text/html")
		switch {
		case r.URL.Path == "/":
			links := `<a href="/p1">p1</a>`
			if r.Header.Get("X-Role") == "alice" {
				links += ` <a href="/mine">mine</a>`
			}
			fmt.Fprintf(w, `<html><title>home</title>%s</html>`, links)
		case r.URL.Path == "/p1":
			fmt.Fprint(w, `<html><title>p1</title>page</html>`)
		case r.URL.Path == "/mine" && r.Header.Get("X-Role") == "alice":
			fmt.Fprint(w, `<html><title>mine</title>alice's page</html>`)
		case r.URL.Path == "/mine":
			http.Redirect(w, r, "/login", http.StatusFound) // a hop of the replay
		case r.URL.Path == "/login":
			fmt.Fprint(w, `<html><title>login</title>sign in</html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	dir := t.TempDir()
	_, errOut, err := captureBoth(t, func() error {
		_, e := captureStdout(t, func() error {
			return cmdRoles([]string{"-dir", dir, "-role", "anon", "-role", "alice=X-Role: alice", "-role", "bob=X-Role: bob", "--", "-url", site.URL + "/", "-no-paths"})
		})
		return e
	})
	if err != nil && exitCode(err) != exitPartial { // bob's session looks dead: a note, exit 3
		t.Fatalf("%v\n%s", err, errOut)
	}
	count := regexp.MustCompile(`^azhaq (run|roles): .*? · (\d+) requests`)
	var perRole []int
	agg := -1
	for _, l := range strings.Split(errOut, "\n") {
		if m := count.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[2])
			if m[1] == "run" {
				perRole = append(perRole, n)
			} else {
				agg = n
			}
		}
	}
	sum := 0
	for _, n := range perRole {
		sum += n
	}
	hops := 0
	for _, r := range log.all() {
		if r.path == "/login" {
			hops++
		}
	}
	target := 0
	_ = ledger.Read(filepath.Join(dir, "roles.ledger.jsonl"), func(e ledger.Entry) error {
		if e.Kind != ledger.KindSeal && e.Class != ledger.ClassSource && e.Class != ledger.ClassDNS && e.Class != ledger.ClassOwn {
			target++
		}
		return nil
	})
	served := len(log.all())
	if len(perRole) != 3 || agg != served || agg != target || sum >= agg {
		t.Errorf("per role %v (%d), all %d, the site served %d, ledger target lines %d\n%s", perRole, sum, agg, served, target, errOut)
	}
	if hops == 0 {
		t.Errorf("the replay followed no redirect: the hop is not counted by this test")
	}
}

// Under -json stderr holds the summary only: the roles' runs print nothing,
// and the summary says what they did not finish (unreachable, skipped,
// failed, notes).
func TestRolesJSONStderrIsTheSummaryAndSaysWhatTheRunsDidNotFinish(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><title>home</title><a href="/skipme/1">skip</a> <a href="/p">p</a></html>`)
			return
		}
		fmt.Fprint(w, `<html><title>p</title>page</html>`)
	}))
	defer site.Close()
	dead := "http://" + deadAddr(t) + "/"
	_, errOut, err := captureBoth(t, func() error {
		_, e := captureStdout(t, func() error {
			return cmdRoles([]string{"-json", "-dir", t.TempDir(), "-role", "anon", "-role", "alice=X-Role: alice", "--", "-url", site.URL + "/", "-url", dead,
				"-allow", "127.0.0.1", "-no-paths", "-deny-path", "^/skipme/"})
		})
		return e
	})
	lines := strings.Split(strings.TrimSpace(errOut), "\n")
	if len(lines) != 1 {
		t.Fatalf("stderr under -json is the summary and nothing else, got %d lines: %q", len(lines), errOut)
	}
	rep := lastReport(t, errOut)
	if rep.Type != "summary" || rep.Command != "roles" {
		t.Errorf("summary %+v", rep)
	}
	if !slices.Contains(rep.Unreachable, strings.TrimSuffix(dead, "/")) && !slices.Contains(rep.Unreachable, dead) {
		t.Errorf("unreachable %q does not name %s (err %v)", rep.Unreachable, dead, err)
	}
	if !slices.ContainsFunc(rep.Skipped, func(s engine.Skip) bool { return strings.Contains(s.Reason, "-deny-path") }) {
		t.Errorf("skipped %+v does not say the -deny-path rule", rep.Skipped)
	}
	if len(rep.Failed) == 0 || len(rep.Notes) == 0 {
		t.Errorf("failed %+v, notes %q", rep.Failed, rep.Notes)
	}
}

// A run that replayed no write, whose histories hold POST, PUT or PATCH
// requests, ends its next with the command that would replay them and what
// that costs: each write with every other role's session and the owner's
// object read around it, as the plan counts them.
func TestRolesNextPassNamesTheWritesOfTheHistoriesNotReplayed(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":1,"note":"n"}`)
	}))
	defer site.Close()
	j := "Content-Type"
	alice := writeHAR(t, "a.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/items/1", "", 200, "Authorization", "Bearer alice"),
		harEntry("2026-10-29T10:00:01.000Z", "PUT", site.URL+"/items/1", `{"note":"a"}`, 200, "Authorization", "Bearer alice", j, "application/json"),
		harEntry("2026-10-29T10:00:02.000Z", "POST", site.URL+"/items", `{"note":"a"}`, 201, "Authorization", "Bearer alice", j, "application/json"))
	bob := writeHAR(t, "b.har",
		harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/items/2", "", 200, "Authorization", "Bearer bob"),
		harEntry("2026-10-29T10:00:01.000Z", "PATCH", site.URL+"/items/2", `{"note":"b"}`, 200, "Authorization", "Bearer bob", j, "application/json"))
	hist := []string{"-har", "alice=" + alice, "-har", "bob=" + bob}
	_, rep, err := rolesRows(t, site.URL, hist...)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range log.all() {
		if r.method != "GET" {
			t.Errorf("a write without -replay-writes: %s %s", r.method, r.path)
		}
	}
	// 3 writes, 3 roles (anon, alice, bob): at least 3 × 2 other roles; the
	// reads of the owner's object around them depend on the answers.
	var next string
	for _, n := range rep.Next {
		if strings.Contains(n, "-replay-writes post,put,patch") {
			next = n
		}
	}
	want := "   (next pass, not run: 3 writes in the histories were not replayed with the other roles' sessions: at least 6 requests more (one for each write and other role, a floor: the reads that check them come on top), and each changes data on the target)"
	if !strings.HasSuffix(next, want) || !strings.HasPrefix(next, "azhaq roles ") || !strings.Contains(next, "-har alice="+alice) {
		t.Errorf("next %q\nwant ...%s", rep.Next, want)
	}
	// The plan of that pass counts the same.
	out, _, _ := cli(t, append([]string{"roles", "-plan", "-json", "-replay-writes", "post,put,patch"}, hist...)...)
	var plan struct {
		Estimate struct {
			Stages []struct {
				Stage    string `json:"stage"`
				Estimate struct {
					Requests int64 `json:"requests"`
				} `json:"estimate"`
			} `json:"stages"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var planned int64
	for _, s := range plan.Estimate.Stages {
		if s.Stage == stageWrites {
			planned += s.Estimate.Requests
		}
	}
	if planned != 6 {
		t.Errorf("the plan's write stage of that pass counts %d requests, the next line's floor says 6", planned)
	}
}

// A role reads an endpoint when it gets a 2xx answer that is not an error;
// any 4xx, an error answered 2xx, a refusal page and a redirect to a
// sign-in page are refusals, and a 3xx or 5xx is neither.
func TestRolesReadsAndRefusalsByAnswer(t *testing.T) {
	for _, c := range []struct {
		name          string
		a             answer
		reads, refuse bool
	}{
		{"200", answer{Status: 200}, true, false},
		{"204", answer{Status: 204}, true, false},
		{"200 shaped as an error", answer{Status: 200, Error: true}, false, true},
		{"200 refusal page", answer{Status: 200, Refusal: true}, false, true},
		{"400", answer{Status: 400}, false, true},
		{"401", answer{Status: 401}, false, true},
		{"403", answer{Status: 403}, false, true},
		{"404", answer{Status: 404}, false, true},
		{"422", answer{Status: 422}, false, true},
		{"499", answer{Status: 499}, false, true},
		{"redirect to a sign-in page", answer{Status: 302, toLogin: true}, false, true},
		{"another redirect", answer{Status: 302, Location: "/home"}, false, false},
		{"500", answer{Status: 500}, false, false},
		{"503", answer{Status: 503}, false, false},
	} {
		if got := reads(c.a); got != c.reads {
			t.Errorf("%s: reads %v, want %v", c.name, got, c.reads)
		}
		if got := refused(c.a); got != c.refuse {
			t.Errorf("%s: refused %v, want %v", c.name, got, c.refuse)
		}
	}
	// A shaped error is told from a body, whatever its status says.
	for body, isError := range map[string]bool{`{"status":"error","data":"nope"}`: true, `{"id":5,"status":"failed","total":3}`: false} {
		if got := reads(answerOf(200, []byte(body), "application/json")); got == isError {
			t.Errorf("%s: a 2xx answer reads %v", body, got)
		}
	}
}

// With -all every endpoint compared is a row, the four verdicts of what
// needs no attention appear, and without it the rows listed and the note
// that counts the rest add up to the endpoints compared.
func TestRolesAllListsEveryEndpointAndTheNoteCountsTheRest(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-Role")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			links := `<a href="/same">s</a> <a href="/gone">g</a> <a href="/data">d</a> <a href="/members">m</a>`
			if role == "alice" {
				links += ` <a href="/mine">mine</a>`
			}
			fmt.Fprintf(w, `<html><title>home</title>%s</html>`, links)
		case "/same":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>same</title>for everyone</html>`)
		case "/data":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"who":%q}`, role)
		case "/members":
			if role == "" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"sign in"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"members":[]}`)
		case "/mine":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>mine</title>alice's</html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	args := func(extra ...string) []string {
		return append(append([]string{"-replay=false"}, extra...), "-role", "anon", "-role", "alice=X-Role: alice", "-role", "bob=X-Role: bob",
			"--", "-url", site.URL+"/", "-no-paths")
	}
	shown, rep, err := rolesRows(t, site.URL, args()...)
	if err != nil {
		t.Fatal(err)
	}
	every, _, err := rolesRows(t, site.URL, args("-all")...)
	if err != nil {
		t.Fatal(err)
	}
	var note string
	for _, n := range rep.Notes {
		if strings.Contains(n, "more endpoints compared and not listed") {
			note = n
		}
	}
	hidden := map[string]int{}
	for k, r := range every {
		if _, ok := shown[k]; !ok {
			hidden[r.Verdict]++
		}
	}
	n := 0
	var parts []string
	for _, v := range []string{verdictData, verdictSame, verdictNone, verdictUnanswered} {
		if hidden[v] == 0 {
			t.Errorf("-all lists no %q row; the rows are %d", v, len(every))
		}
		n += hidden[v]
	}
	for _, v := range sortedCountKeys(hidden) {
		parts = append(parts, fmt.Sprintf("%d %s", hidden[v], v))
	}
	wantNote := fmt.Sprintf("%d more endpoints compared and not listed (%s); -all lists them", n, strings.Join(parts, ", "))
	if len(hidden) != 4 || note != wantNote || len(every) != len(shown)+n || len(shown) == 0 {
		t.Errorf("%d rows listed and %d with -all; hidden %v\nnote %q\nwant %q", len(shown), len(every), hidden, note, wantNote)
	}
	for k, r := range shown {
		if !listed(r.Verdict) {
			t.Errorf("%s is listed with the verdict %q", k, r.Verdict)
		}
	}
	// The summary counts the verdicts of the rows listed.
	counts := map[string]int{}
	for _, r := range shown {
		counts[r.Verdict]++
	}
	if !reflect.DeepEqual(rep.Counts, counts) || rep.Results != len(shown) {
		t.Errorf("summary counts %v (%d results), the rows listed hold %v", rep.Counts, rep.Results, counts)
	}
}

// An object anyone reads, signed in or not, is listed once for its route;
// -all lists every one.
func TestRolesAllListsEveryObjectOfARouteThatAnyoneReads(t *testing.T) {
	spec := `{"openapi":"3.0.0","info":{"title":"items","version":"1"},"paths":{"/api/items":{"get":{}},
		"/api/items/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, `{"name":"items"}`)
		case r.URL.Path == "/openapi.json":
			fmt.Fprint(w, spec)
		case r.URL.Path == "/api/items":
			fmt.Fprint(w, `{"items":[{"id":1},{"id":2},{"id":3}]}`)
		case strings.HasPrefix(r.URL.Path, "/api/items/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/items/")
			if id == "1" || id == "2" || id == "3" {
				fmt.Fprintf(w, `{"id":%s,"name":"item %s"}`, id, id)
				return
			}
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not found"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer site.Close()
	count := func(extra ...string) int {
		rows, _, err := rolesRows(t, site.URL, append(extra, "-role", "anon", "-role", "alice=X-Role: alice", "-role", "bob=X-Role: bob", "--", "-url", site.URL+"/")...)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rows {
			if r.Verdict == verdictPublicObj {
				n++
			}
		}
		return n
	}
	one, every := count(), count("-all")
	if one != 1 || every != 3 {
		t.Errorf("rows for an object anyone reads: %d by default, %d with -all, want 1 and 3", one, every)
	}
}

// The text table writes the roles and fields of a row in brackets.
func TestRolesTheTextTableWritesTheRolesAndFieldsInBrackets(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice"}, {name: "bob"}, {name: "admin"}}
	st := func(n ...int) map[string]answer {
		return map[string]answer{"anon": {Status: n[0]}, "alice": {Status: n[1]}, "bob": {Status: n[2]}, "admin": {Status: n[3]}}
	}
	rows := []roleRow{
		{URL: "http://h/debug", Verdict: verdictAnyoneSecrets, Sensitive: []string{"password"}, Answers: st(200, 200, 200, 200)},
		{URL: "http://h/n/1", Verdict: verdictCross, Readers: []string{"bob", "admin"}, Owner: "alice", Answers: st(401, 200, 200, 200)},
		{URL: "http://h/c/1", Verdict: verdictAnyID, Owner: "alice", Control: &control{Value: "1000014", Alike: []string{"bob"}}, Answers: st(401, 200, 200, 401)},
		{URL: "http://h/u", Verdict: verdictSecrets, Readers: []string{"alice", "bob"}, Sensitive: []string{"deluxeToken"}, Answers: st(401, 200, 200, 401)},
		{URL: "http://h/admin", Verdict: verdictOnly, Readers: []string{"admin"}, Answers: st(401, 403, 403, 200)},
		{URL: "http://h/api/items/3", Method: "PUT", Verdict: verdictWriteCross, Readers: []string{"bob"}, Owner: "alice", Answers: st(401, 200, 200, 401)},
	}
	out, _ := captureStdout(t, func() error { printRoles(roles, rows, len(rows), "dir"); return nil })
	for _, want := range []string{
		"[anyone reads sensitive fields: password]",
		"[bob, admin read alice's object]",
		"[answers any identifier: bob read alice's object and a made-up 1000014 alike]",
		"[alice, bob read the same sensitive fields: deluxeToken]",
		"[only admin reads it]",
		"[bob writes alice's object]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %s in\n%s", want, out)
		}
	}
}

// The "Listed" column of the write verdicts says whether a row shows by
// default or only with -all.
func TestRolesTheListedColumnOfTheWriteVerdictsIsWhatListedSays(t *testing.T) {
	raw, err := os.ReadFile("../../docs/commands/roles.md")
	if err != nil {
		t.Fatal(err)
	}
	_, table, _ := strings.Cut(string(raw), "#### Write verdicts")
	table, _, _ = strings.Cut(table, "\n## ")
	all := []string{verdictWriteAnyone, verdictWriteCross, verdictWriteUnread, verdictWriteDry, verdictWriteNoChange, verdictWriteCreate, verdictWriteAccepted,
		verdictWriteUnverifiable, verdictWriteOwner, verdictWriteVoid, verdictWriteRefused, verdictWriteFailed, verdictWriteMixed,
		verdictWriteRedirected, verdictWriteMixedRedirect}
	seen := 0
	for _, l := range strings.Split(table, "\n") {
		cells := strings.Split(l, "|")
		if len(cells) < 4 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "`") {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		col := strings.Trim(strings.TrimSpace(cells[2]), "`")
		if !slices.Contains(all, name) {
			t.Errorf("the table names a verdict the code has not: %q", name)
			continue
		}
		seen++
		if col != "yes" && col != "-all" || listed(name) != (col == "yes") {
			t.Errorf("%q: the table says %q, listed() says %v", name, col, listed(name))
		}
	}
	if seen != len(all) {
		t.Errorf("the table lists %d verdicts, the code has %d", seen, len(all))
	}
}

// Without -canary a role's session is checked on an endpoint the anonymous
// role was refused, and never on one the anonymous role reads alike.
func TestRolesACanaryIsNeverAnEndpointTheAnonymousRoleReadsAlike(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}
	j := func(status int, body string) answer {
		a, _ := readAnswer(status, []byte(body), "application/json")
		return a
	}
	own := map[string]bool{"h": true}
	answers := map[string]map[string]answer{
		"anon":  {"http://h/api/news": j(200, `{"items":[1]}`), "http://h/api/cards": j(401, `{"error":"sign in"}`), "http://h/api/other": j(200, `{"items":[2]}`)},
		"alice": {"http://h/api/news": j(200, `{"items":[1]}`), "http://h/api/cards": j(200, `{"data":[]}`), "http://h/api/other": j(200, `{"items":[3]}`)},
	}
	got := pickCanaries(roles, answers, nil, nil, own)
	if c := got["alice"]; c == nil || c.url != "http://h/api/cards" {
		t.Errorf("an endpoint the anonymous role was refused: %+v", got["alice"])
	}
	// Only what the anonymous role reads alike (or reads at all) is left: none is picked.
	delete(answers["anon"], "http://h/api/cards")
	delete(answers["alice"], "http://h/api/cards")
	delete(answers["anon"], "http://h/api/other")
	delete(answers["alice"], "http://h/api/other")
	if got := pickCanaries(roles, answers, nil, nil, own); got["alice"] != nil {
		t.Errorf("a canary %+v on an endpoint the anonymous role reads alike", got["alice"])
	}
}

// A role's session is renewed at most 5 times, and not again once a new
// session fails its first check.
func TestRolesASessionIsRenewedAtMostFiveTimesAndNotAfterANewOneFails(t *testing.T) {
	run := func(life int, renewable bool) (renewals int, notes []string, sent int, w *replayWatch) {
		fetch.Reset()
		var mu sync.Mutex
		used := map[string]int{}
		site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			tok := r.Header.Get("Authorization")
			alive := tok == "t1" || renewable && strings.HasPrefix(tok, "t") && tok != "t1"
			if r.URL.Path != "/me" {
				used[tok]++
			}
			if !alive || used[tok] > life {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"expired"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/me" {
				fmt.Fprint(w, `{"name":"alice"}`)
				return
			}
			fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
		}))
		defer site.Close()
		me, _ := readAnswer(200, []byte(`{"name":"alice"}`), "application/json")
		roles := []role{{name: "alice", headers: []string{"Authorization: t1"}, session: http.Header{"Authorization": {"t1"}}}}
		answers := map[string]map[string]answer{"alice": {}}
		found := map[string][]string{}
		for i := 1; i <= 80; i++ {
			found[fmt.Sprintf("%s/o/%02d", site.URL, i)] = []string{"bob"}
		}
		w = &replayWatch{every: 3, canaries: map[string]*canary{"alice": {url: site.URL + "/me", want: me}}, renew: func(i int) error {
			renewals++
			roles[i].session = http.Header{"Authorization": {fmt.Sprintf("t%d", renewals+1)}}
			return nil
		}}
		var err error
		sent, err = replayAll(roles, answers, found, nil, map[string]bool{"127.0.0.1": true}, 0, 1000, w)
		if err != nil {
			t.Fatal(err)
		}
		return renewals, w.notes, sent, w
	}
	// Every token serves 4 requests; the replay needs many tokens, and gets 5.
	if n, notes, _, w := run(4, true); n != 5 || !w.failed || !strings.Contains(strings.Join(notes, "\n"), "did not come back") {
		t.Errorf("renewals %d, notes %q", n, notes)
	}
	// A new session that is dead at its first check is the last one asked for.
	if n, notes, _, _ := run(4, false); n != 1 {
		t.Errorf("a new session that fails its first check: %d renewals, notes %q", n, notes)
	}
}

// A signed-in role with nothing to check its session by is named in a note.
func TestRolesARoleWithNothingToCheckItsSessionByIsNamedInANote(t *testing.T) {
	var log reqLog
	site := crawlSite(t, &log, 2)
	_, rep, err := rolesRows(t, site.URL, "-role", "anon", "-role", "alice=X-Role: alice", "--", "-url", site.URL+"/", "-no-paths")
	if err != nil {
		t.Fatal(err)
	}
	want := "role alice: nothing only its session reads was found to check it by during the replay; -canary URL gives one"
	if !slices.Contains(rep.Notes, want) {
		t.Errorf("notes %q", rep.Notes)
	}
}

// A role whose session was lost is paused: the rest of its replay is not
// attempted, and its answers there are status 0.
func TestRolesAPausedRoleHasStatusZeroForWhatWasNotAttempted(t *testing.T) {
	site := expiringApp(t, 4)
	rows, rep, err := rolesRows(t, site.URL, "-all", "-canary-every", "3", "-role", "anon", "-role-cmd", "alice="+counter(t, "alice"), "-role", "bob=Authorization: Bearer bob-fixed",
		"--", "-url", site.URL+"/")
	if exitCode(err) != exitPartial {
		t.Errorf("exit %d (%v)", exitCode(err), err)
	}
	zero := 0
	for k, r := range rows {
		if r.Status["bob"] == 0 {
			zero++
			if _, ok := r.Answers["bob"]; ok {
				t.Errorf("%s has an answer of bob's with status 0: %+v", k, r.Answers["bob"])
			}
			if r.Status["alice"] == 0 {
				t.Errorf("%s: alice has status 0 as well", k)
			}
		}
	}
	notes := strings.Join(rep.Notes, "\n")
	if zero == 0 || !strings.Contains(notes, "role bob: its remaining replay was paused on session loss") || !strings.Contains(notes, "not-attempted, status 0") {
		t.Errorf("%d rows where bob was not attempted; notes\n%s", zero, notes)
	}
}

// When no signed-in role reads what the visitor is refused, each role is
// judged alone: dead when refused on every endpoint the visitor is refused
// and given nothing more than the visitor, alive when it read an endpoint
// the visitor did not, or was forbidden (403) where the visitor was asked to
// sign in (401). Beside a role that does read what the visitor is refused,
// a role refused there is dead whatever else it read.
func TestRolesRolesJudgedAloneAreAliveWhenTheSiteKnewThem(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}
	ok := func(h string) answer { return answer{Status: 200, Length: 10, Hash: h} }
	no := func(s int) answer { return answer{Status: s} }
	for _, c := range []struct {
		name  string
		roles []role
		rows  map[string][]answer // an answer per role, in order
		dead  []string
	}{
		{"refused where the visitor is, nothing more", roles, map[string][]answer{"/a": {no(401), no(401)}, "/": {ok("h"), ok("h")}}, []string{"alice"}},
		{"it read what the visitor did not", roles, map[string][]answer{"/a": {no(401), no(401)}, "/n/1": {no(404), ok("n1")}, "/": {ok("h"), ok("h")}}, nil},
		{"forbidden where the visitor was asked to sign in", roles, map[string][]answer{"/a": {no(401), no(403)}, "/": {ok("h"), ok("h")}}, nil},
		{"forbidden, beside a role that reads it", []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"A: 2"}}},
			map[string][]answer{"/a": {no(401), ok("a"), no(403)}, "/n/2": {no(404), no(404), ok("n2")}, "/": {ok("h"), ok("h"), ok("h")}}, []string{"bob"}},
	} {
		var rs []roleRow
		for u, as := range c.rows {
			row := roleRow{URL: "http://h" + u, Answers: map[string]answer{}}
			for i, r := range c.roles {
				row.Answers[r.name] = as[i]
			}
			rs = append(rs, row)
		}
		if got := deadRoles(c.roles, rs); !reflect.DeepEqual(got, c.dead) {
			t.Errorf("%s: dead %v, want %v", c.name, got, c.dead)
		}
	}
}

// A made-up identifier counts as answered as a real object only when the
// status is 2xx and the answer is neither an error nor a refusal, for the
// control and for the real read it is compared with.
func TestRolesAMadeUpIdentifierIsAnsweredLikeARealObjectOnlyByARead(t *testing.T) {
	real := answerOf(200, []byte(`{"id":7,"name":"shoes","owner":"alice"}`), "application/json")
	same := answerOf(200, []byte(`{"id":7,"name":"shoes","owner":"alice"}`), "application/json")
	body := []byte(`{"id":7,"name":"shoes","owner":"alice"}`)
	if !answersAnything(same, real, body, "1000007") {
		t.Fatal("the same body is answered alike")
	}
	for name, c := range map[string]answer{
		"404":         answerOf(404, body, "application/json"),
		"500":         answerOf(500, body, "application/json"),
		"redirect":    {Status: 302, Hash: same.Hash},
		"an error":    {Status: 200, Hash: same.Hash, Error: true},
		"a refusal":   {Status: 200, Hash: same.Hash, Refusal: true},
		"a 4xx page":  {Status: 403, Hash: same.Hash},
		"a 2xx error": answerOf(200, []byte(`{"status":"error","data":"no such item"}`), "application/json"),
	} {
		if answersAnything(c, real, body, "1000007") {
			t.Errorf("%s was answered like a real object", name)
		}
	}
	refused := real
	refused.Refusal = true
	if answersAnything(same, refused, body, "1000007") {
		t.Error("a control is no object when the real read was a refusal")
	}
}

// A refusal page is told by its status, what it says and its JSON fields,
// and by the body's hash too when the page does not change.
func TestRolesARefusalPageIsAlsoToldByItsHashWhenItDoesNotChange(t *testing.T) {
	page := func(hash string) answer {
		return answer{Status: 200, Hash: hash, Title: "Access denied", said: "Access denied", Length: 90}
	}
	anon := map[string]answer{"http://h/a": page("same"), "http://h/b": page("same"), "http://h/c": page("same")}
	user := answer{Status: 200, Hash: "mine", Title: "A", said: "A"}
	answers := map[string]map[string]answer{"anon": anon, "alice": {"http://h/a": user, "http://h/b": user, "http://h/c": user}}
	pages := learnRefusals([]role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}, answers)
	if len(pages) != 1 || pages[0].hash != "same" || pages[0].urls != 3 {
		t.Fatalf("pages %+v", pages)
	}
	// Same body, said another way: the hash tells it.
	odd := answer{Status: 200, Hash: "same", said: "something else"}
	if !matchesPage("http://h/z", odd, pages) {
		t.Error("a page with the refusal page's hash is the refusal page")
	}
	// A page that changes (a token in it) is told by what it says alone.
	anon["http://h/b"] = page("other")
	pages = learnRefusals([]role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}, answers)
	if len(pages) != 1 || pages[0].hash != "" {
		t.Fatalf("a changing page: %+v", pages)
	}
	if matchesPage("http://h/z", odd, pages) {
		t.Error("a page that changes is told by its hash")
	}
	if !matchesPage("http://h/z", page("whatever"), pages) {
		t.Error("a page that changes is told by what it says")
	}
}

// -id without a role is tried like an identifier the answers held (asked of
// every role, no role's object); with a role it names that role's object.
func TestRolesAnIDWithoutARoleIsTriedAndOwnsNothing(t *testing.T) {
	var log reqLog
	spec := `{"openapi":"3.0.0","info":{"title":"shop","version":"1"},"paths":{"/rest/basket/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/":
			fmt.Fprint(w, `{"name":"shop"}`)
		case r.URL.Path == "/openapi.json":
			fmt.Fprint(w, spec)
		case r.URL.Path == "/rest/basket/6" && r.Header.Get("X-Role") != "":
			fmt.Fprint(w, `{"id":6,"items":["socks"]}`)
		default:
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"sign in"}`)
		}
	}))
	defer site.Close()
	run := func(id string) roleRow {
		rows, _, err := rolesRows(t, site.URL, "-id", id, "-role", "anon", "-role", "alice=X-Role: alice", "-role", "bob=X-Role: bob", "--", "-url", site.URL+"/openapi.json", "-no-paths")
		if err != nil {
			t.Fatal(err)
		}
		return rows[" /rest/basket/6"]
	}
	got := run("basket_id=6")
	asked := map[string]bool{}
	for _, r := range log.all() {
		if r.path == "/rest/basket/6" {
			asked[r.role] = true
		}
	}
	if !asked["alice"] || !asked["bob"] || !asked[""] || got.Owner != "" || got.Verdict == verdictCross || len(got.Status) != 3 {
		t.Errorf("an -id without a role: asked %v, row %+v", asked, got)
	}
	if got := run("alice:basket_id=6"); got.Owner != "alice" || got.Verdict != verdictCross || !slices.Equal(got.Readers, []string{"bob"}) {
		t.Errorf("an -id with a role names that role's object: %+v", got)
	}
}

// An answer has its say on whose an object is only when the answers of
// every role that reads it agree.
func TestRolesAnObjectsOwnAnswerSpeaksOnlyWhenEveryReaderGetsTheSame(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}, {name: "bob", headers: []string{"B: 1"}}}
	who := whoFrom(nil, map[string]string{"alice": `{"sub":"27"}`, "bob": `{"sub":"28"}`})
	named := func(id int) answer {
		return answerOf(200, []byte(fmt.Sprintf(`{"id":1,"UserId":%d}`, id)), "application/json")
	}
	settle := func(alice, bob answer) instance {
		made := map[string]instance{"http://h/x/1": {owner: "alice", by: "in alice's answers alone", sure: hinted}}
		settleOwners(roles, made, map[string]map[string]answer{"alice": {"http://h/x/1": alice}, "bob": {"http://h/x/1": bob}}, who)
		return made["http://h/x/1"]
	}
	if in := settle(named(28), named(28)); in.owner != "bob" || !strings.Contains(in.by, "UserId 28 names bob") {
		t.Errorf("answers that agree name the owner: %+v", in)
	}
	if in := settle(named(28), named(27)); in.owner != "alice" || in.by != "in alice's answers alone" {
		t.Errorf("answers that differ say nothing: %+v", in)
	}
}

// An account, a customer or a member is not the user: its identifier is
// matched with the session's own of that name, never with its user id.
func TestRolesAMemberIDIsNotAUserID(t *testing.T) {
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: 1"}}}
	for _, c := range []struct {
		claims, body, owner string
	}{
		{`{"sub":"27"}`, `{"id":3,"memberId":27}`, ""},
		{`{"sub":"27","member_id":27}`, `{"id":3,"memberId":27}`, "alice"},
		{`{"sub":"27"}`, `{"id":3,"customerId":27}`, ""},
		{`{"sub":"27"}`, `{"id":3,"accountId":27}`, ""},
		{`{"sub":"27"}`, `{"id":3,"userId":27}`, "alice"},
	} {
		who := whoFrom(nil, map[string]string{"alice": c.claims})
		a := answerOf(200, []byte(c.body), "application/json")
		if owner, by, _, _ := whose(a.self, roles, who, "", ""); owner != c.owner {
			t.Errorf("%s with %s: owner %q (%s), want %q", c.body, c.claims, owner, by, c.owner)
		}
	}
}

// A -role-cmd command's own requests are not azhaq's: the target sees them,
// the ledger and the summary do not count them, and no scope holds them (it
// reaches a host the run's -allow leaves out).
func TestRolesARoleCmdsOwnRequestsAreNotInTheLedgerOrHeldToTheScope(t *testing.T) {
	var log reqLog
	var mu sync.Mutex
	var cmdHosts []string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.URL.Path == "/cmdping" {
			mu.Lock()
			cmdHosts = append(cmdHosts, r.Host)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>home</title></html>`)
	}))
	defer site.Close()
	port := strings.TrimPrefix(site.URL, "http://127.0.0.1:")
	dir := t.TempDir()
	cmd := fmt.Sprintf(`curl -s http://localhost:%s/cmdping >/dev/null; echo "Authorization: Bearer tok"`, port)
	out, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", dir, "-role", "anon", "-role-cmd", "bob=" + cmd, "--", "-url", site.URL + "/", "-no-paths"})
	})
	_ = out
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	mu.Lock()
	pings := len(cmdHosts)
	mu.Unlock()
	if pings == 0 || !strings.HasPrefix(cmdHosts[0], "localhost:") {
		t.Fatalf("the command's request did not reach the site: %v", cmdHosts)
	}
	inLedger := 0
	_ = ledger.Read(filepath.Join(dir, "roles.ledger.jsonl"), func(e ledger.Entry) error {
		if strings.Contains(e.Target, "/cmdping") {
			inLedger++
		}
		return nil
	})
	if inLedger != 0 || int(rep.Requests) != len(log.all())-pings {
		t.Errorf("the ledger holds %d of the command's requests; the summary says %d requests, the site saw %d (%d of them the command's)", inLedger, rep.Requests, len(log.all()), pings)
	}
}

// -role-cmd is not offered over MCP: the tools take a role's headers or a
// sign-in, and a command in a role is not passed on.
func TestRolesRoleCmdIsNotOfferedOverMCP(t *testing.T) {
	var schema string
	for _, tool := range mcpTools() {
		if tool["name"] == "azhaq_roles" || tool["name"] == "azhaq_roles_writes" {
			raw, _ := json.Marshal(tool)
			schema += string(raw)
		}
	}
	if schema == "" {
		t.Fatal("no roles tool")
	}
	for _, bad := range []string{"role-cmd", "role_cmd", `"cmd"`, `"command"`} {
		if strings.Contains(schema, bad) {
			t.Errorf("the roles tools offer %s", bad)
		}
	}
	dir := t.TempDir()
	s := &mcpServer{exe: fakeAzhaq(t, dir), dir: dir, lock: []string{"-allow", "127.0.0.1"}, locked: true, budget: 50, started: true}
	roles := []any{map[string]any{"name": "anon"}, map[string]any{"name": "bob", "cmd": "echo X-Role: bob", "command": "echo hi", "role_cmd": "echo hi"}}
	callText(t, s, "azhaq_roles", map[string]any{"url": "http://127.0.0.1:18090/", "roles": roles})
	raw, _ := os.ReadFile(filepath.Join(dir, "args"))
	if strings.Contains(string(raw), "-role-cmd") {
		t.Errorf("a command was passed on to roles: %s", raw)
	}
}

// vulnerableNotes is an app where any signed-in session writes any note: a
// PUT sets the note at its path, and a GET shows it.
func vulnerableNotes(t *testing.T, log *reqLog) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	notes := map[string]string{}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"sign in"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			var m map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &m)
			notes[r.URL.Path] = m["note"]
		}
		w.Header().Set("Content-Type", "application/json")
		n, ok := notes[r.URL.Path]
		if !ok {
			n = "first"
		}
		fmt.Fprintf(w, `{"id":%q,"note":%q}`, r.URL.Path, n)
	}))
	t.Cleanup(site.Close)
	return site
}

// -replay-writes asks each role's writes with every other role's session,
// after the reads, and a cross write it proves is always proved.
func TestRolesWritesAreAskedWithEveryOtherRoleAfterTheReads(t *testing.T) {
	var log reqLog
	site := vulnerableNotes(t, &log)
	har := func(file, user string, write bool) string {
		es := []map[string]any{harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/items/"+user, "", 200, "Authorization", "Bearer "+user)}
		if write {
			es = append(es, harEntry("2026-10-29T10:00:01.000Z", "PUT", site.URL+"/items/"+user, `{"note":"pwned"}`, 200, "Authorization", "Bearer "+user, "Content-Type", "application/json"))
		}
		return writeHAR(t, file, es...)
	}
	rows, _, err := rolesRows(t, site.URL, "-replay-writes", "put", "-har", "alice="+har("a.har", "alice", true), "-har", "bob="+har("b.har", "bob", false), "-har", "carol="+har("c.har", "carol", false))
	if err != nil {
		t.Fatal(err)
	}
	puts := map[string]int{}
	firstPut, lastReplayRead := -1, -1
	for i, r := range log.all() {
		switch {
		case r.method == "PUT":
			puts[r.auth]++
			if firstPut < 0 {
				firstPut = i
			}
		case r.method == "GET" && r.auth != "Bearer alice":
			lastReplayRead = i // the replay's reads: the owner's read-backs are alice's
		}
	}
	if puts[""] != 1 || puts["Bearer bob"] != 1 || puts["Bearer carol"] != 1 || puts["Bearer alice"] != 0 || len(puts) != 3 {
		t.Errorf("alice's PUT was sent %v: once with each other role's session, not with hers again", puts)
	}
	if firstPut < 0 || lastReplayRead > firstPut {
		t.Errorf("a write (request %d) was sent before the replay's reads ended (request %d)", firstPut, lastReplayRead)
	}
	row := rows["PUT /items/alice"]
	// carol's write sets what bob's already did: nothing more to read back for her.
	if row.Verdict != verdictWriteCross || !slices.Equal(row.Readers, []string{"bob"}) || row.Confidence != confProved || row.Status["anon"] != 401 || row.Status["carol"] != 200 {
		t.Errorf("the row: %+v", row)
	}
}

// Writes go only to the hosts of the run options' -url values, or to the
// scope -allow names: a write the history sent to another host is not sent
// there, and is when the run options name that host.
func TestRolesWritesGoOnlyToTheHostsOfTheTargetsOrTheScope(t *testing.T) {
	var log reqLog
	site := vulnerableNotes(t, &log)
	other := strings.Replace(site.URL, "127.0.0.1", "localhost", 1)
	run := func(extra ...string) int {
		log.mu.Lock()
		log.list = nil
		log.mu.Unlock()
		har := func(file, user string) string {
			return writeHAR(t, file,
				harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/items/"+user, "", 200, "Authorization", "Bearer "+user),
				harEntry("2026-10-29T10:00:01.000Z", "GET", site.URL+"/items/"+user+"/x", "", 200, "Authorization", "Bearer "+user),
				harEntry("2026-10-29T10:00:02.000Z", "GET", site.URL+"/items/"+user+"/y", "", 200, "Authorization", "Bearer "+user),
				harEntry("2026-10-29T10:00:03.000Z", "PUT", other+"/elsewhere/"+user, `{"note":"x"}`, 200, "Authorization", "Bearer "+user, "Content-Type", "application/json"),
				harEntry("2026-10-29T10:00:04.000Z", "PUT", site.URL+"/items/"+user, `{"note":"x"}`, 200, "Authorization", "Bearer "+user, "Content-Type", "application/json"))
		}
		args := append([]string{"-replay-writes", "put", "-har", "alice=" + har("a.har", "alice"), "-har", "bob=" + har("b.har", "bob")}, extra...)
		if _, rep, err := rolesRows(t, site.URL, args...); err != nil {
			t.Fatalf("%v: %+v", err, rep.Notes)
		}
		n := 0
		for _, r := range log.all() {
			if r.method == "PUT" && strings.HasPrefix(r.path, "/elsewhere/") {
				n++
			}
		}
		return n
	}
	if n := run(); n != 0 {
		t.Errorf("%d writes were sent to a host that is not a target", n)
	}
	if n := run("--", "-url", site.URL+"/", "-no-paths", "-allow", "127.0.0.1", "-allow", "localhost"); n == 0 {
		t.Error("no write was sent to a host the run options' -allow names")
	}
}

// Every write request counts against -replay-max, the budget and the rate,
// and none follows a redirect.
func TestRolesEveryWriteRequestIsCountedPacedAndNotRedirected(t *testing.T) {
	fetch.Reset()
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.URL.Path == "/elsewhere" {
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer site.Close()
	h := func(v string) http.Header { return http.Header{"Authorization": {v}} }
	roles := []role{{name: "anon"}, {name: "alice", session: h("alice")}, {name: "bob", session: h("bob")}, {name: "carol", session: h("carol")}}
	var reqs []writeReq
	for _, p := range []string{"/n/1", "/n/2", "/n/3"} {
		reqs = append(reqs, writeReq{owner: "alice", method: "PUT", url: site.URL + p, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"x"}`), status: 200})
	}
	own := map[string]bool{"127.0.0.1": true}
	rows, sent, err := replayWrites(roles, reqs, nil, own, 0, 100, false)
	if err != nil || len(rows) != 3 || sent != len(log.all()) {
		t.Fatalf("sent %d, the site saw %d: %v", sent, len(log.all()), err)
	}
	for _, r := range log.all() {
		if r.path == "/elsewhere" {
			t.Errorf("a redirect was followed: %+v", r)
		}
	}
	// A budget of 4: the site sees no more.
	log.mu.Lock()
	log.list = nil
	log.mu.Unlock()
	_, sent, err = replayWrites(roles, reqs, nil, own, 0, 4, false)
	if sent != 4 || len(log.all()) != 4 || !errors.Is(err, errReplayMax) {
		t.Errorf("a budget of 4: sent %d, the site saw %d, err %v", sent, len(log.all()), err)
	}
	// At 20 requests a second, the requests are spread over the time they take.
	log.mu.Lock()
	log.list = nil
	log.mu.Unlock()
	start := time.Now()
	_, sent, _ = replayWrites(roles, reqs, nil, own, 20, 100, false)
	if min := time.Duration(sent-4) * 50 * time.Millisecond * 9 / 10; time.Since(start) < min { // a burst of rate/5 first
		t.Errorf("%d requests at 20 a second took %v, at least %v", sent, time.Since(start), min)
	}
}

// The field a canary sets is the first by name that is not an identifier, an
// owner or reference field, a credential or a timestamp; a field the user
// names is taken before any other; a body with none is sent as recorded.
func TestRolesTheCanaryFieldIsTheFirstThatNoRuleLeavesOut(t *testing.T) {
	body := map[string]any{"zname": "z", "note": "n", "email": "e@x.test", "username": "u", "owner": "o", "createdBy": "c", "userId": "1", "BasketId": "2",
		"password": "p", "createdAt": "2026-10-27T10:00:00Z", "stamp": "1700000000", "aaa": "", "count": 3}
	field, left := canaryField(body, nil)
	var names []string
	for _, l := range left {
		names = append(names, l.name)
	}
	sort.Strings(names)
	if field != "note" || !reflect.DeepEqual(names, []string{"BasketId", "createdAt", "createdBy", "email", "owner", "password", "stamp", "userId", "username"}) {
		t.Errorf("field %q, left alone %v", field, names)
	}
	if field, _ := canaryField(body, []string{"Email"}); field != "email" {
		t.Errorf("a named field comes first: %q", field)
	}
	if field, _ := canaryField(map[string]any{"b": "1", "a": "2"}, nil); field != "a" {
		t.Errorf("the first by name: %q", field)
	}
	only := []byte(`{"email":"a@x.test","userId":"3","password":"p","at":"2026-10-27T10:00:00Z"}`)
	if out, f, ok := withCanary(only, "azhaq-1"); ok || f != "" || string(out) != string(only) {
		t.Errorf("no field qualifies: %s %q %v", out, f, ok)
	}
	if out, f, ok := withCanary(only, "azhaq-1", "email"); !ok || f != "email" || !strings.Contains(string(out), `"email":"azhaq-1"`) {
		t.Errorf("a named field: %s %q %v", out, f, ok)
	}
}

// The canary is never on by default, and the field it set is not restored.
func TestRolesTheCanaryIsOffByDefaultAndItsFieldIsNotRestored(t *testing.T) {
	if f := flagsOf("roles").Lookup("replay-writes-canary"); f == nil || f.DefValue != "false" {
		t.Errorf("-replay-writes-canary default: %+v", f)
	}
	fetch.Reset()
	var mu sync.Mutex
	note := "hello"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			var m map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &m)
			note = m["note"]
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":3,"note":%q}`, note)
	}))
	defer srv.Close()
	h := func(v string) http.Header { return http.Header{"A": {v}} }
	roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	u := srv.URL + "/api/notes/3"
	before, _ := readAnswer(200, []byte(`{"id":3,"note":"hello"}`), "application/json")
	put := writeReq{owner: "alice", method: "PUT", url: u, header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"note":"hello"}`), status: 200}
	for _, canary := range []bool{false, true} {
		note = "hello"
		rows, _, _ := replayWrites(roles, []writeReq{put}, map[string]map[string]answer{"alice": {u: before}}, map[string]bool{"127.0.0.1": true}, 0, 100, canary)
		mu.Lock()
		got := note
		mu.Unlock()
		if canary != strings.HasPrefix(got, "azhaq-") || (canary && rows[0].Verdict != verdictWriteCross) {
			t.Errorf("canary %v: the note is %q after the replay, the row %q", canary, got, rows[0].Verdict)
		}
	}
}

// A row that does not prove a write ranks below the proved reads and the
// proved cross writes above them; what shows by default is what listed says.
func TestRolesTheRowsThatProveNothingRankBelowTheProvedReads(t *testing.T) {
	top := []string{verdictWriteAnyone, verdictWriteCross}
	below := []string{verdictWriteCreate, verdictWriteAccepted, verdictWriteNoChange}
	for _, v := range top {
		for _, read := range []string{verdictAnyoneSecrets, verdictCross, verdictAnyID, verdictObject, verdictSignedIn, verdictStatus} {
			if verdictOrder[v] >= verdictOrder[read] {
				t.Errorf("%q does not rank above %q", v, read)
			}
		}
	}
	for _, v := range below {
		for _, read := range []string{verdictCross, verdictAnyID} {
			if verdictOrder[v] <= verdictOrder[read] {
				t.Errorf("%q does not rank below %q", v, read)
			}
		}
	}
	if !listed(verdictWriteCreate) || !listed(verdictWriteAccepted) || listed(verdictWriteNoChange) {
		t.Error("the creates are listed, the write that changed nothing is not")
	}
}

// A sign-in step is sent only because the user asked for it by flag, a
// write that is let and cannot be read back is accepted-not-verified without
// one, and a step proves the write only for the role whose write it proved.
func TestRolesAVerificationStepIsSentOnlyWhenAskedAndProvesOnlyItsRole(t *testing.T) {
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	var logins atomic.Int64
	app := passwordApp(t, false)
	counted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/login" {
			logins.Add(1)
		}
		app.Config.Handler.ServeHTTP(w, r)
	}))
	defer counted.Close()
	obj := counted.URL + "/users/alice"
	before, _ := readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	put := writeReq{owner: "alice", method: "PUT", url: counted.URL + "/users/alice/password", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"password":"n3w"}`), status: 204, from: "alice.har"}
	own := map[string]bool{"127.0.0.1": true}
	rows, _, err := replayWritesVerify(nil, roles, []writeReq{put}, map[string]map[string]answer{"alice": {obj: before}}, own, 0, 100, false, nil)
	if err != nil || len(rows) != 1 || logins.Load() != 0 {
		t.Fatalf("rows %+v err %v, %d sign-ins without the flag", rows, err, logins.Load())
	}
	if r := rows[0]; r.Verdict != verdictWriteUnread || r.WriteVerification != verifyAccepted {
		t.Errorf("a write that was let and nothing proved: %q, %q", r.Verdict, r.WriteVerification)
	}
	steps, _ := parseVerifyWrites([]string{"login:" + counted.URL + "/users/login"})
	if _, _, err := replayWritesVerify(nil, roles, []writeReq{put}, map[string]map[string]answer{"alice": {obj: before}}, own, 0, 100, false, steps); err != nil || logins.Load() == 0 {
		t.Errorf("with the flag: %d sign-ins, %v", logins.Load(), err)
	}

	// Two roles are let; the step proves the write only where its read of the
	// owner's profile shows the change: carol may not read it.
	var mu sync.Mutex
	emails := map[string]string{"alice": "alice@x.test"}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get("A")
		if caller == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut:
			var m map[string]string
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &m)
			emails["alice"] = m["email"]
			w.WriteHeader(204)
		case strings.HasPrefix(r.URL.Path, "/profile/") && caller != "bob":
			w.WriteHeader(403)
		case strings.HasPrefix(r.URL.Path, "/profile/"):
			fmt.Fprintf(w, `{"email":%q}`, emails[strings.TrimPrefix(r.URL.Path, "/profile/")])
		default:
			fmt.Fprint(w, `{"username":"alice"}`)
		}
	}))
	defer site.Close()
	two := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "carol", headers: []string{"A: carol"}, session: h("carol")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	steps, _ = parseVerifyWrites([]string{"read:" + site.URL + "/profile/{owner};field=email"})
	obj = site.URL + "/users/alice"
	before, _ = readAnswer(200, []byte(`{"username":"alice"}`), "application/json")
	put = writeReq{owner: "alice", method: "PUT", url: site.URL + "/users/alice/email", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"email":"new@x.test"}`), status: 204, from: "alice.har"}
	rows, _, err = replayWritesVerify(nil, two, []writeReq{put}, map[string]map[string]answer{"alice": {obj: before}}, own, 0, 100, false, steps)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	if r := rows[0]; r.Verdict != verdictWriteCross || !slices.Equal(r.Readers, []string{"bob"}) || r.WriteVerification != verifyProved || r.Status["carol"] != 204 ||
		strings.Contains(r.OwnerBy, "carol's write is proved") {
		t.Errorf("the step proved bob's write alone: readers %v, %q, %q", r.Readers, r.WriteVerification, r.OwnerBy)
	}
}

// The report keeps the word a write row says for its verification.
func TestRolesReportKeepsTheWriteVerificationWord(t *testing.T) {
	const u = "https://s.test/users/v1/alice/password"
	for _, word := range []string{verifyProved, verifyAccepted, verifyRefuted} {
		row := roleRow{URL: u, Method: "PUT", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictWriteUnread, Confidence: confProved, WriteVerification: word,
			Answers: map[string]answer{"alice": {Status: 204}, "bob": {Status: 204}}}
		er := evRow(t, row, ans("alice", "answer", u, 204, "", "curl -sS -i -X PUT '"+u+"' -H \"Authorization: Bearer $ALICE_TOKEN\""),
			ans("bob", "answer", u, 204, "", "curl -sS -i -X PUT '"+u+"' -H \"Authorization: Bearer $BOB_TOKEN\""))
		d, err := buildReport(er, []string{"alice", "bob"}, time.Time{}, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d.markdown(), "- Write verification: "+word+".") {
			t.Errorf("%s: the report lacks the word:\n%s", word, d.markdown())
		}
	}
}

// An empty write whose owner's object cannot be read to verify it is
// answered 2xx but changed nothing, said to be unread, not a finding.
func TestRolesAnEmptyWriteOnAnObjectThatCannotBeReadChangedNothingOfTheOwners(t *testing.T) {
	fetch.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
	roles := []role{{name: "anon"}, {name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
	put := writeReq{owner: "alice", method: "PATCH", url: srv.URL + "/api/items/3", header: http.Header{}, body: []byte("{}"), empty: true, from: "PATCH /api/items/{id} with an empty body"}
	rows, _, err := replayWrites(roles, []writeReq{put}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	r := rows[0]
	if r.Verdict != verdictWriteNoChange || listed(r.Verdict) || !strings.Contains(r.OwnerBy, "the owner's object could not be read to verify the write") {
		t.Errorf("verdict %q, owner_by %q", r.Verdict, r.OwnerBy)
	}
}

// A create is located from the answer's Location, then a link, then an
// identifier in its body, then what the write set, and only then from the
// collection as the creator read it before and after; no member URL is
// tried that none of them names.
func TestRolesACreateIsLocatedInOrderAndWithoutGuessingAMemberURL(t *testing.T) {
	var log reqLog
	exists := map[string]bool{}
	var answerFor func() (string, string) // the create answer's body and Location
	var mu sync.Mutex
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		caller := r.Header.Get("A")
		if caller == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost:
			body, loc := answerFor()
			if loc != "" {
				w.Header().Set("Location", loc)
			}
			w.WriteHeader(201)
			fmt.Fprint(w, body)
		case r.URL.Path == "/books/v1":
			fmt.Fprint(w, `{"books":[]}`)
		case exists[strings.TrimPrefix(r.URL.Path, "/books/v1/")]:
			fmt.Fprintf(w, `{"book_title":%q,"owner":%q}`, strings.TrimPrefix(r.URL.Path, "/books/v1/"), caller)
		default:
			w.WriteHeader(404)
		}
	}))
	defer site.Close()
	post := writeReq{owner: "alice", method: "POST", url: site.URL + "/books/v1", header: http.Header{"Content-Type": {"application/json"}}, body: []byte(`{"book_title":"W"}`), status: 201}
	for _, c := range []struct {
		name, body, loc string
		exist           []string
		how             string
	}{
		{"all of them", `{"link":"/books/v1/K","id":"A"}`, "/books/v1/L", []string{"L", "K", "A", "W"}, "readable back at /books/v1/L (the create answer's Location)"},
		{"no Location", `{"link":"/books/v1/K","id":"A"}`, "", []string{"K", "A", "W"}, "readable back at /books/v1/K (the create answer's link)"},
		{"no link", `{"id":"A"}`, "", []string{"A", "W"}, "readable back at /books/v1/A (the create answer's id)"},
		{"the write's", `{}`, "", []string{"W"}, "readable back at /books/v1/W (the write's book_title)"},
	} {
		mu.Lock()
		exists = map[string]bool{}
		for _, e := range c.exist {
			exists[e] = true
		}
		answerFor = func() (string, string) { return c.body, c.loc }
		mu.Unlock()
		rows, _, err := replayWrites(bookRoles(), []writeReq{post}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		if err != nil || len(rows) != 1 || !strings.Contains(rows[0].OwnerBy, c.how) {
			t.Errorf("%s: err %v, rows %+v, want %q", c.name, err, rows, c.how)
		}
	}
	// Nothing names a member: only the collection and the identifiers the
	// write set are read, no member URL is made up.
	mu.Lock()
	exists = map[string]bool{}
	answerFor = func() (string, string) { return `{}`, "" }
	mu.Unlock()
	log.mu.Lock()
	log.list = nil
	log.mu.Unlock()
	rows, _, _ := replayWrites(bookRoles(), []writeReq{post}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if len(rows) != 1 || rows[0].Verdict != verdictWriteUnverifiable {
		t.Fatalf("%+v", rows)
	}
	for _, r := range log.all() {
		if r.method == "GET" && r.path != "/books/v1" && r.path != "/books/v1/W" {
			t.Errorf("a member URL that nothing names was tried: %s", r.path)
		}
	}
}

// What a create made is a cross read with confidence guess when the
// read-back does not say whose it is.
func TestRolesACreatedObjectThatDoesNotSayWhoseItIsIsAGuess(t *testing.T) {
	var mu sync.Mutex
	var readBy []string // who read the created object, as the server answered it
	books := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("A") == "" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost:
			var in struct {
				Title string `json:"book_title"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			books[in.Title] = true
			w.Header().Set("Location", "/books/v1/"+in.Title)
			w.WriteHeader(201)
		case r.URL.Path == "/books/v1":
			fmt.Fprint(w, `{"books":[]}`)
		case books[strings.TrimPrefix(r.URL.Path, "/books/v1/")]:
			readBy = append(readBy, r.Header.Get("A"))
			fmt.Fprintf(w, `{"book_title":%q}`, strings.TrimPrefix(r.URL.Path, "/books/v1/"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	roles := bookRoles()
	rows, _, err := replayWrites(roles, []writeReq{bookPost(srv, `{"book_title":"b1"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	made := map[string]instance{}
	objs := createdRows(roles, rows, made)
	if len(objs) != 1 {
		t.Fatalf("created rows %+v", objs)
	}
	explain(objs, made, roles, nil)
	if o := objs[0]; o.Verdict != verdictCross || o.Confidence != confGuess || !strings.Contains(o.OwnerBy, "created by bob's replayed POST /books/v1") {
		t.Errorf("verdict %q confidence %q owner_by %q", o.Verdict, o.Confidence, o.OwnerBy)
	}
	// Every role but its creator read the object, once.
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(readBy, ","); got != "bob,alice" {
		t.Errorf("the object was read by %s: its creator to locate it, then each other role once", got)
	}
}

// The reads of the object a create made count against the budget like every
// replay request.
func TestRolesTheReadsOfACreatedObjectCountAgainstTheBudget(t *testing.T) {
	srv, _ := newBookApp("", true)
	defer srv.Close()
	var served atomic.Int64
	counted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		srv.Config.Handler.ServeHTTP(w, r)
	}))
	defer counted.Close()
	_, full, err := replayWrites(bookRoles(), []writeReq{bookPost(srv, `{"book_title":"b1"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, 100, false)
	if err != nil || full < 6 {
		t.Fatalf("a full run sent %d: %v", full, err)
	}
	served.Store(0)
	_, sent, err := replayWrites(bookRoles(), []writeReq{bookPost(counted, `{"book_title":"b2"}`)}, nil, map[string]bool{"127.0.0.1": true}, 0, full-2, false)
	if sent != full-2 || served.Load() != int64(sent) || !errors.Is(err, errReplayMax) {
		t.Errorf("a budget of %d: sent %d, the site saw %d, err %v", full-2, sent, served.Load(), err)
	}
}

// A kept body has what a role sent, its sensitive values and its tokens
// replaced by a tag: the same value shows the same tag within a run, and the
// tag is keyed for the run, so it tells nothing of the value.
func TestRolesAKeptBodyHasItsSecretsReplacedByATagThatTellsNothing(t *testing.T) {
	roles := []role{{name: "alice", session: http.Header{"Authorization": {"Bearer alice-secret-token"}, "Cookie": {"sid=alice-cookie-value; theme=dark"}}}}
	one, two := newRedactor(roles), newRedactor(roles)
	body := []byte(`{"by":"alice-secret-token","c":"alice-cookie-value","password":"hunter2hunter2","jwt":"` + jwt(`{"sub":"x"}`) + `","name":"visible"}`)
	got := string(one.body(body))
	for _, leaked := range []string{"alice-secret-token", "alice-cookie-value", "hunter2hunter2", "eyJ"} {
		if strings.Contains(got, leaked) {
			t.Errorf("%q is kept: %s", leaked, got)
		}
	}
	if !strings.Contains(got, `"name":"visible"`) || strings.Count(got, "[redacted ") != 4 {
		t.Errorf("what is not a secret stays: %s", got)
	}
	tag := regexp.MustCompile(`\[redacted [0-9a-f]{8}\]`)
	a, b := tag.FindAllString(string(one.body(body)), -1), tag.FindAllString(string(one.body(body)), -1)
	if !slices.Equal(a, b) || len(a) != 4 {
		t.Errorf("the same value gets the same tag within a run: %v %v", a, b)
	}
	if c := tag.FindAllString(string(two.body(body)), -1); slices.Equal(a, c) {
		t.Errorf("another run gives the same tags %v: a tag that does not depend on the run can be tried against guesses", c)
	}
	if one.tag("alice-secret-token") == "alice-secret-token" || strings.Contains(one.tag("alice-secret-token"), "alice") {
		t.Error("the tag holds the value")
	}
}

// roles show tells how a body differs from the owner's, field by field, at
// most 20 lines: - the owner's only, + this role's only, ~ a changed value.
func TestRolesShowDiffLinesAreAtMostTwentyAndTellWhoHoldsWhat(t *testing.T) {
	owner := []byte(`{"data":{"id":19,"name":"alice"},"only_owner":1,"same":true}`)
	other := []byte(`{"data":{"id":19,"name":"bob"},"detail":"No authorization token provided","same":true}`)
	lines, more, ok := jsonDiff(owner, other, 20)
	var got []string
	for _, l := range lines {
		got = append(got, l.String())
	}
	want := []string{`~ data.name  "alice" → "bob"`, `+ detail  "No authorization token provided"`, `- only_owner  1`}
	if !ok || more != 0 || !slices.Equal(got, want) {
		t.Errorf("diff %q (%d more, ok %v), want %q", got, more, ok, want)
	}
	var a, b strings.Builder
	a.WriteString("{")
	b.WriteString("{")
	for i := 0; i < 27; i++ {
		fmt.Fprintf(&a, `"f%02d":%d,`, i, i)
		fmt.Fprintf(&b, `"f%02d":%d,`, i, i+100)
	}
	a.WriteString(`"end":1}`)
	b.WriteString(`"end":1}`)
	lines, more, ok = jsonDiff([]byte(a.String()), []byte(b.String()), 20)
	if !ok || len(lines) != 20 || more != 7 {
		t.Errorf("27 differences: %d lines and %d more, want 20 and 7", len(lines), more)
	}
}

// roles show -body prints the body the role got, as kept, and nothing else.
func TestRolesShowBodyPrintsTheBodyAndNothingElse(t *testing.T) {
	alice, bob := jwt(`{"sub":"alice"}`), jwt(`{"sub":"bob"}`)
	site := objectApp(t, map[string]string{alice: "alice", bob: "bob"})
	dir := t.TempDir()
	if _, _, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", dir, "-role", "anon", "-role", "alice=Authorization: Bearer " + alice, "-role", "bob=Authorization: Bearer " + bob,
			"--", "-url", site.URL + "/"})
	}); err != nil {
		t.Fatal(err)
	}
	body, err := captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, "-body", "bob", site.URL + "/api/notes/21"}) })
	if want := regexp.MustCompile(`^\{"id":21,"owner":"alice","secret":"\[redacted [0-9a-f]{8}\]"\}$`); err != nil || !want.MatchString(body) {
		t.Errorf("bob's body, as kept, and no other byte: %q (%v)", body, err)
	}
}

// A stage of the plan that cannot be counted before says not_counted, and
// the plan as a whole says it is at least that much.
func TestRolesThePlanSaysWhatItCannotCountBefore(t *testing.T) {
	a := writeHAR(t, "a.har", harEntry("2026-10-29T10:00:00.000Z", "GET", "http://127.0.0.1:9/x/1", "", 200, "Authorization", "Bearer a"))
	b := writeHAR(t, "b.har", harEntry("2026-10-29T10:00:00.000Z", "GET", "http://127.0.0.1:9/x/2", "", 200, "Authorization", "Bearer b"))
	out, _, _ := cli(t, "roles", "-plan", "-json", "-har", "alice="+a, "-har", "bob="+b, "-replay-writes", "put")
	var plan struct {
		Estimate struct {
			AtLeast bool `json:"at_least"`
			Stages  []struct {
				Stage      string `json:"stage"`
				AtLeast    bool   `json:"estimate_at_least"`
				NotCounted string `json:"not_counted"`
			} `json:"stages"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := map[string]string{}
	for _, s := range plan.Estimate.Stages {
		if s.NotCounted != "" && s.AtLeast {
			got[s.Stage] = s.NotCounted
		}
	}
	for _, stage := range []string{"replay", "controls", "write replay"} {
		if got[stage] == "" {
			t.Errorf("the %s stage cannot be counted before and does not say so: %+v", stage, plan.Estimate.Stages)
		}
	}
	if !plan.Estimate.AtLeast || got["history reads"] != "" {
		t.Errorf("the history reads are counted exactly, the plan is a floor: %+v", plan.Estimate)
	}
}

// A control request a -deny-path rule keeps out is the rule's, not a failure:
// the row and a note say it, and the exit is not changed.
func TestRolesADeniedControlIsSaidOnTheRowAndInANoteAndIsNotAFailure(t *testing.T) {
	alice, bob := jwt(`{"sub":"alice"}`), jwt(`{"sub":"bob"}`)
	site := objectApp(t, map[string]string{alice: "alice", bob: "bob"})
	_, rows, rep, err := rolesJSONReport(t, site.URL, "-role", "anon", "-role", "alice=Authorization: Bearer "+alice, "-role", "bob=Authorization: Bearer "+bob,
		"--", "-url", site.URL+"/", "-deny-path", `^/api/notes/10000`)
	if err != nil || rep.Exit != exitOK {
		t.Fatalf("exit %d (%v), notes %q", rep.Exit, err, rep.Notes)
	}
	note := rows["/api/notes/21"]
	if note.Verdict != verdictCross || note.Control == nil || len(note.Control.Failed) != 1 || !strings.Contains(note.Control.Failed[0], "-deny-path") ||
		!strings.Contains(note.Evidence, "could not be asked") {
		t.Errorf("the row: %+v, control %+v, evidence %q", note.Verdict, note.Control, note.Evidence)
	}
	want := "2 cross reads not checked with a made-up identifier: a -deny-path rule keeps its route out"
	if !slices.Contains(rep.Notes, want) {
		t.Errorf("notes %q, want %q", rep.Notes, want)
	}
}

// rolesJSONReport is rolesJSON with the summary as a report.
func rolesJSONReport(t *testing.T, site string, args ...string) (map[string]string, map[string]roleRow, report, error) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return cmdRoles(append([]string{"-json", "-dir", t.TempDir()}, args...)) })
	labels, rows := map[string]string{}, map[string]roleRow{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var row roleRow
		if json.Unmarshal([]byte(l), &row) != nil {
			t.Fatalf("not a row: %s", l)
		}
		p := strings.TrimPrefix(row.URL, site)
		labels[p], rows[p] = row.Verdict, row
	}
	return labels, rows, lastReport(t, errOut), err
}

// A short 2xx answer that says no is a refusal for a write, whether it says
// "Only Admins may delete users!" or "forbidden"; a long page is not read as one.
func TestRolesAShortTwoXXAnswerThatSaysNoIsARefusalOfAWrite(t *testing.T) {
	fetch.Reset()
	for _, c := range []struct {
		body    string
		refused bool
	}{
		{"Only Admins may delete users!", true},
		{"forbidden", true},
		{"Forbidden", true},
		{"you are not allowed to do that", true},
		{"deleted", false},
		{strings.Repeat("filler ", 60) + "forbidden", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				fmt.Fprint(w, `{"id":3}`)
				return
			}
			fmt.Fprint(w, c.body)
		}))
		h := func(v string) http.Header { x := http.Header{}; x.Set("A", v); return x }
		roles := []role{{name: "alice", headers: []string{"A: alice"}, session: h("alice")}, {name: "bob", headers: []string{"A: bob"}, session: h("bob")}}
		u := srv.URL + "/api/items/3"
		before, _ := readAnswer(200, []byte(`{"id":3}`), "application/json")
		rows, _, _ := replayWrites(roles, []writeReq{{owner: "alice", method: "DELETE", url: u, header: http.Header{}}}, map[string]map[string]answer{"alice": {u: before}}, map[string]bool{"127.0.0.1": true}, 0, 100, false)
		srv.Close()
		if a := rows[0].Answers["bob"]; a.Refusal != c.refused || reads(a) == c.refused {
			t.Errorf("%q: refusal %v, want %v", truncate(c.body, 30), a.Refusal, c.refused)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// A row's evidence holds owner_by without the routes and without where each
// value was read.
func TestRolesEvidenceHoldsOwnerByWithoutTheRoutesAndWhereEachValueWasRead(t *testing.T) {
	row := roleRow{URL: "http://h/rest/basket/8", From: "http://h/rest/basket/{id}", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, value: "8",
		OwnerBy: "bid claim of alice's token → /rest/basket/{id}; the answer's UserId 27 names alice (data.id claim of alice's token)",
		Answers: map[string]answer{"alice": {Status: 200, Length: 155, Hash: "h"}, "bob": {Status: 200, Length: 155, Hash: "h"}}}
	rows := []roleRow{row}
	explain(rows, map[string]instance{}, []role{{name: "alice"}, {name: "bob"}}, nil)
	want := "bob got alice's answer (the same body, 155 bytes); bid claim of alice's token; the answer's UserId 27 names alice"
	if rows[0].Evidence != want {
		t.Errorf("evidence %q\nwant     %q", rows[0].Evidence, want)
	}
	if strings.Contains(rows[0].Evidence, "→") || strings.Contains(rows[0].Evidence, "data.id claim") {
		t.Errorf("the route or where the value was read is in the evidence: %q", rows[0].Evidence)
	}
}

// The session is checked before the role's replay, every -canary-every
// requests, and after the replay; 0 means no checks.
func TestRolesTheSessionIsCheckedBeforeEveryFewRequestsAndAfterTheReplay(t *testing.T) {
	run := func(every int) string {
		fetch.Reset()
		var log reqLog
		site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.add(r)
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/me" {
				fmt.Fprint(w, `{"name":"alice"}`)
				return
			}
			fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
		}))
		defer site.Close()
		me, _ := readAnswer(200, []byte(`{"name":"alice"}`), "application/json")
		roles := []role{{name: "alice", headers: []string{"Authorization: t"}, session: http.Header{"Authorization": {"t"}}}}
		found := map[string][]string{}
		for i := 1; i <= 9; i++ {
			found[fmt.Sprintf("%s/o/%d", site.URL, i)] = []string{"bob"}
		}
		w := &replayWatch{every: every, canaries: map[string]*canary{"alice": {url: site.URL + "/me", want: me}}}
		if _, err := replayAll(roles, map[string]map[string]answer{"alice": {}}, found, nil, map[string]bool{"127.0.0.1": true}, 0, 100, w); err != nil {
			t.Fatal(err)
		}
		var seq []string
		for _, r := range log.all() {
			seq = append(seq, strings.TrimPrefix(r.path, "/o/"))
		}
		return strings.Join(seq, " ")
	}
	if got, want := run(3), "/me 1 2 3 /me 4 5 6 /me 7 8 9 /me"; got != want {
		t.Errorf("every 3: %s\nwant   %s", got, want)
	}
	if got, want := run(0), "1 2 3 4 5 6 7 8 9"; got != want {
		t.Errorf("-canary-every 0: %s\nwant %s", got, want)
	}
}

// The writes the routes take are PUT and PATCH with an empty JSON object,
// and DELETE with no body.
func TestRolesAMapWriteIsAnEmptyJSONObjectOrNoBody(t *testing.T) {
	made := map[string]instance{"http://app.test/api/items/3": {template: "http://app.test/api/items/{id}", owner: "alice", value: "3"}}
	writes := map[string][]writeOp{"http://app.test/api/items/{id}": {{method: "PUT", bodyType: "json"}, {method: "PATCH", bodyType: "json"}, {method: "DELETE"}}}
	got := mapWrites(made, writes, map[string]bool{"PUT": true, "PATCH": true, "DELETE": true})
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	for _, w := range got {
		switch w.method {
		case "PUT", "PATCH":
			if string(w.body) != "{}" || !w.empty || w.header.Get("Content-Type") != "application/json" {
				t.Errorf("%s: %+v", w.method, w)
			}
		case "DELETE":
			if w.body != nil || w.empty {
				t.Errorf("DELETE: %+v", w)
			}
		}
	}
}

// The replay sends GET requests only, and a GET is sent whatever it is
// named: a page found as /logout is asked with every other role's session.
func TestRolesTheReplayAsksAGETWhateverItIsNamed(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer site.Close()
	alice := writeHAR(t, "a.har", harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/logout", "", 200, "Authorization", "Bearer alice"))
	bob := writeHAR(t, "b.har", harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/me", "", 200, "Authorization", "Bearer bob"))
	if _, _, err := rolesRows(t, site.URL, "-har", "alice="+alice, "-har", "bob="+bob); err != nil {
		t.Fatal(err)
	}
	asked := map[string]bool{}
	for _, r := range log.all() {
		if r.method != "GET" {
			t.Errorf("a request that is no GET: %s %s", r.method, r.path)
		}
		if r.path == "/logout" {
			asked[r.auth] = true
		}
	}
	if !asked["Bearer alice"] || !asked["Bearer bob"] || !asked[""] {
		t.Errorf("/logout was asked with %v", asked)
	}
}

// A logout the history sent is replayed like any write: the method decides,
// not the name, and it goes with each other role's session.
func TestRolesAHistoryLogoutIsReplayedLikeAnyWrite(t *testing.T) {
	var log reqLog
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q}`, r.URL.Path)
	}))
	defer site.Close()
	har := func(file, user string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:00.000Z", "GET", site.URL+"/items/"+user, "", 200, "Authorization", "Bearer "+user),
			harEntry("2026-10-29T10:00:01.000Z", "POST", site.URL+"/logout", "", 200, "Authorization", "Bearer "+user))
	}
	if _, _, err := rolesRows(t, site.URL, "-replay-writes", "post", "-har", "alice="+har("a.har", "alice"), "-har", "bob="+har("b.har", "bob")); err != nil {
		t.Fatal(err)
	}
	posts := map[string]int{}
	for _, r := range log.all() {
		if r.method == "POST" && r.path == "/logout" {
			posts[r.auth]++
		}
	}
	// alice's logout is replayed with bob's session and the visitor's, bob's with alice's and the visitor's.
	if posts["Bearer alice"] != 1 || posts["Bearer bob"] != 1 || posts[""] != 2 || len(posts) != 3 {
		t.Errorf("POST /logout was sent with %v", posts)
	}
}
