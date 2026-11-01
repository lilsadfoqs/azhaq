package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// Contract tests at the seams between commands, where a change on one side
// broke the other. Each is named for the contract it holds.

// verdicts reads the roles verdict constants (name and text) from the
// source, so a verdict added later is found by the test below.
func verdicts(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, f := range []string{"roles.go", "roles_writes.go", "roles_controls.go"} {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if !strings.HasPrefix(n.Name, "verdict") || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, _ := strconv.Unquote(lit.Value)
						out[n.Name] = s
					}
				}
			}
		}
	}
	return out
}

// notReportable are the verdicts azhaq report writes nothing for, each with
// the reason: no finding, or a finding the evidence does not carry.
var notReportable = map[string]string{
	"verdictObject":        "every role reads it: a comparison, not a broken control",
	"verdictSecrets":       "the same fields for every role: no role reads more than another",
	"verdictShared":        "a session that did not find it gets the same answer: no proof either way",
	"verdictSignedIn":      "signed in only: access control working",
	"verdictOnly":          "one role reads it: access control working",
	"verdictRoleGated":     "some roles refused: access control working",
	"verdictFields":        "different fields per role: shaping, not a bypass",
	"verdictPublicObj":     "anyone reads it: public by design until a person says otherwise",
	"verdictStatus":        "status differs: a comparison",
	"verdictData":          "different data per role: a comparison",
	"verdictSame":          "same for every role: nothing differs",
	"verdictNone":          "no role reads it: nothing to report",
	"verdictUnanswered":    "no answer: nothing to report",
	"verdictAnyID":         "the control showed the route answers any identifier, so its 2xx says nothing of who may read what",
	"verdictWriteNoChange": "answered 2xx but changed nothing of the owner's: no proof of a write",
	"verdictWriteOwner":    "only the owner writes: access control working",
	"verdictWriteVoid":     "the owner's own write was refused: no comparison possible",
	"verdictWriteRefused":  "the other roles were refused: access control working",
	"verdictWriteFailed":   "a server error: neither refused nor accepted",
	"verdictWriteDry":      "nothing was sent (-dry-writes)",
}

// Every verdict roles can give has a report class, or is listed here as not
// reportable on purpose: a new verdict cannot be left out of azhaq report
// without someone saying so.
func TestContractEveryRolesVerdictHasAReportClass(t *testing.T) {
	all := verdicts(t)
	if len(all) < 20 {
		t.Fatalf("read only %d verdicts from the source: %v", len(all), all)
	}
	for name, text := range all {
		class, _ := classOf(text)
		why, skipped := notReportable[name]
		switch {
		case class != "" && skipped:
			t.Errorf("%s has the report class %s and is also listed as not reportable (%s)", name, class, why)
		case class == "" && !skipped:
			t.Errorf("%s (%q) has no report class: give classOf a class for it, or list it in notReportable with the reason", name, text)
		}
	}
	for name := range notReportable {
		if _, ok := all[name]; !ok {
			t.Errorf("notReportable names %s, which is no verdict", name)
		}
	}
}

// portProducers make a workspace each by a different route: ports, run
// -ports and the ingest of a naabu scan.
func portProducers(t *testing.T, web string) map[string]string {
	t.Helper()
	t.Chdir(t.TempDir())
	dir := t.TempDir()
	dbs := map[string]string{}
	do := func(name string, args ...string) {
		db := filepath.Join(dir, name+".db")
		dbs[name] = db
		if _, errOut, code := cli(t, append(args, "-db", db, "-json")...); code != exitOK {
			t.Fatalf("%s: exit %d: %s", name, code, errOut)
		}
	}
	do("ports", "ports", "-host", "127.0.0.1", "-p", web)
	do("run", "run", "-list", hostsFile(t, "127.0.0.1"), "-ports", web, "-sources", "none")
	naabu := writeFile(t, t.TempDir(), "naabu.json", fmt.Sprintf(`{"ip":"127.0.0.1","port":%s,"protocol":"tcp","tls":false}`+"\n", web))
	do("ingest", "ingest", naabu)
	return dbs
}

// Every producer of ports (ports, run -ports, the ingest of a naabu scan)
// makes Port rows that query, export and the MCP server list, as rows of
// what was asked about.
func TestContractPortProducersMakePortRowsThatQueryExportAndMCPList(t *testing.T) {
	web := portsServer(t)
	dbs := portProducers(t, web)
	key := "127.0.0.1:" + web + "/tcp"
	dir := t.TempDir()
	exe := filepath.Join(dir, "azhaq")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nAZHAQ_TEST_AS_MAIN=1 exec '"+os.Args[0]+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &mcpServer{exe: exe, dir: dir}
	for name, db := range dbs {
		out, _, code := runContract(t, "query", "-db", db, "-type", "Port", "-scope", "target")
		var found bool
		for _, r := range jsonRows(t, out) {
			found = found || r["key"] == key && r["type"] == "Port"
		}
		if code != exitOK || !found {
			t.Errorf("%s: query -type Port -scope target does not list %s:\n%s", name, key, out)
		}
		exp, _, err := captureBoth(t, func() error { return run([]string{"export", "-db", db, "-format", "jsonl"}) })
		if err != nil || !strings.Contains(exp, `"type":"Port","key":"`+key+`"`) {
			t.Errorf("%s: export -format jsonl lacks the Port %s (%v):\n%.300s", name, key, err, exp)
		}
		raw, err := os.ReadFile(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".db"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		text, isErr := callText(t, s, "azhaq_query", map[string]any{"workspace": name, "type": []any{"Port"}, "scope": "target"})
		if isErr || !strings.Contains(text, key) {
			t.Errorf("%s: azhaq_query type Port does not list %s: %v\n%.300s", name, key, isErr, text)
		}
	}
}

// An open web port reaches the HTTP stage before the sweep of the other
// ports ends: the page is asked while a silent port is still being probed.
func TestContractOpenWebPortReachesTheHTTPStageBeforeTheSweepEnds(t *testing.T) {
	web := portsServer(t)
	silent, err := net.Listen("tcp", "127.0.0.1:0") // accepts and says nothing
	if err != nil {
		t.Skip(err)
	}
	var held sync.WaitGroup
	t.Cleanup(func() { silent.Close(); held.Wait() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			held.Add(1)
			go func() { defer held.Done(); time.Sleep(10 * time.Second); c.Close() }()
		}
	}()
	_, quiet, _ := net.SplitHostPort(silent.Addr().String())
	t.Chdir(t.TempDir())
	led := filepath.Join(t.TempDir(), "w.ledger.jsonl")
	_, rep, code := runContract(t, "run", "-list", hostsFile(t, "127.0.0.1"), "-ports", web+","+quiet, "-probe", "-web-scheme", "http", "-no-paths",
		"-sources", "none", "-timeout", "60s", "-ledger", led, "-db", "w.db")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: %+v", code, rep)
	}
	var page, sweepEnd time.Time
	_ = ledger.Read(led, func(e ledger.Entry) error {
		switch {
		case e.Collector == "azhaq-http" && e.Target == "http://127.0.0.1:"+web+"/" && page.IsZero():
			page = e.Time
		case e.Collector == "azhaq-ports":
			sweepEnd = e.Time
		}
		return nil
	})
	if page.IsZero() || sweepEnd.IsZero() {
		t.Fatalf("the ledger has no page request (%v) or no port line (%v)", page, sweepEnd)
	}
	if !page.Before(sweepEnd) {
		t.Errorf("the web port's page was asked at %s, after the sweep's last connection at %s", page.Format("15:04:05.000"), sweepEnd.Format("15:04:05.000"))
	}
}

// outsideSite is a page that links, loads a script and sends a form to a
// second port of the same host.
func outsideSite(t *testing.T) (inside, outside string, outsideHits *atomic.Int32) {
	t.Helper()
	outsideHits = &atomic.Int32{}
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		fmt.Fprint(w, "x")
	}))
	t.Cleanup(b.Close)
	bu, _ := url.Parse(b.URL)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><title>in</title><a href="/x">x</a> <a href="%s/secret">out</a> <script src="%s/s.js"></script><img src="%s/i.png"></html>`, b.URL, b.URL, b.URL)
		case "/x":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>x</title></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	au, _ := url.Parse(a.URL)
	return au.Port(), bu.Port(), outsideHits
}

// No output row (text, -json, -jsonl, -stream, the map, any export) names a
// host and port outside the scope, and nothing is sent there.
func TestContractNoOutputRowNamesAHostPortOutsideTheScope(t *testing.T) {
	in, out, hits := outsideSite(t)
	t.Chdir(t.TempDir())
	scopeArgs := []string{"-allow", "127.0.0.1:" + in}
	named := regexp.MustCompile(`127\.0\.0\.1:` + out + `\b`)
	check := func(what, text string) {
		t.Helper()
		if named.MatchString(text) {
			t.Errorf("%s names 127.0.0.1:%s, outside -allow 127.0.0.1:%s:\n%.600s", what, out, in, text)
		}
	}
	site := "http://127.0.0.1:" + in + "/"
	for name, args := range map[string][]string{
		"run text":    {"run", "-url", site, "-sources", "none", "-db", "t.db"},
		"run json":    {"run", "-url", site, "-sources", "none", "-json", "-db", "j.db"},
		"run stream":  {"run", "-url", site, "-sources", "none", "-stream", "-db", "s.db"},
		"crawl text":  {"crawl", "-u", site},
		"crawl json":  {"crawl", "-u", site, "-json"},
		"crawl jsonl": {"crawl", "-u", site, "-jsonl"},
	} {
		stdout, _, code := cli(t, append(append(args, scopeArgs...), "-ledger", "off")...)
		if code != exitOK {
			t.Errorf("%s: exit %d", name, code)
		}
		check(name, stdout)
	}
	for _, format := range []string{"jsonl", "urls", "hosts", "names", "targets", "html", "graphml", "secrets", "burp", "openapi"} {
		stdout, _, _ := cli(t, "export", "-db", "j.db", "-format", format)
		check("export -format "+format, stdout)
	}
	for _, q := range [][]string{{"query", "-db", "j.db"}, {"query", "-db", "j.db", "-json"}, {"query", "-db", "j.db", "-type", "URL", "-jsonl"}} {
		stdout, _, _ := cli(t, q...)
		check(strings.Join(q, " "), stdout)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the port outside the scope was asked %d times", n)
	}
}

// -stream says each name, address, URL and port as it is found: its keys
// are the keys of the map rows the run ends with.
func TestContractStreamKeysEqualTheMapKeys(t *testing.T) {
	in, _, _ := outsideSite(t)
	t.Chdir(t.TempDir())
	stdout, _, code := cli(t, "run", "-url", "http://127.0.0.1:"+in+"/", "-allow", "127.0.0.1:"+in, "-sources", "none", "-stream", "-json", "-db", "s.db")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	streamed, mapped := map[string]bool{}, map[string]bool{}
	for _, r := range jsonRows(t, stdout) {
		key, _ := r["key"].(string)
		if r["type"] == "found" {
			streamed[key] = true
		} else {
			mapped[key] = true
		}
	}
	if len(streamed) == 0 || len(mapped) == 0 {
		t.Fatalf("stream %v, map %v", streamed, mapped)
	}
	if !equalSets(streamed, mapped) {
		t.Errorf("the stream keys %v are not the map keys %v", keysOf(streamed), keysOf(mapped))
	}
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
