package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/hunt"
	"github.com/lilsadfoqs/azhaq/store"
)

// everyKindSite answers what hunt proves from one answer each: a 500 with SQL
// error text, a 500 debug page, a directory listing, a GraphQL endpoint that
// reads its schema, and a shop whose basket any signed-in role reads.
func everyKindSite() *httptest.Server {
	const schema = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"subscriptionType":null,
"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"pastes"},{"name":"me"}]},
{"name":"Mutation","kind":"OBJECT","fields":[{"name":"createPaste"}]},
{"name":"Paste","kind":"OBJECT","fields":[{"name":"title"}]},
{"name":"String","kind":"SCALAR","fields":null}]}}}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>Acme</title><body><a href="/orders">a</a> <a href="/render">b</a> <a href="/files/">c</a> <a href="/graphql">d</a></body></html>`)
		case r.URL.Path == "/orders":
			w.WriteHeader(500)
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>Error</title><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''' at line 1</body></html>`)
		case r.URL.Path == "/render":
			w.WriteHeader(500)
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><title>Error</title><body><h1>Werkzeug Debugger</h1><p>The debugger caught an exception in your WSGI application.</p></body></html>`)
		case r.URL.Path == "/files/":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="a.txt">a.txt</a></body></html>`)
		case r.URL.Path == "/graphql" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, schema)
		case r.URL.Path == "/graphql":
			w.WriteHeader(400)
			io.WriteString(w, `{"errors":[{"message":"Must provide query string."}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

// everyKindWorkspace runs the site into a workspace, and returns it with the run's
// summary and a -roles file whose verdict is proved, with the roles run's
// directory beside it.
func everyKindWorkspace(t *testing.T) (site *httptest.Server, db string, rep report, rolesFile string) {
	t.Helper()
	site = everyKindSite()
	t.Cleanup(site.Close)
	t.Chdir(t.TempDir())
	db = filepath.Join(t.TempDir(), "k.db")
	var code int
	_, rep, code = runContract(t, "run", "-url", site.URL+"/", "-db", db, "-allow", "127.0.0.1", "-graphql", "-no-tech", "-no-paths", "-no-favicon", "-sources", "none", "-ledger", "off")
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v", code, rep.Failed)
	}
	u := site.URL + "/rest/basket/4711"
	body := `{"id":4711,"owner":"carol","items":["juice"]}`
	curl := "curl -sS -i '" + u + "' -H \"Authorization: Bearer $BOB_TOKEN\""
	row := roleRow{URL: u, From: site.URL + "/rest/basket/{id}", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, Confidence: confProved,
		Evidence: "bob read alice's basket", Status: map[string]int{"alice": 200, "bob": 200},
		Answers: map[string]answer{"alice": {Status: 200, Length: len(body)}, "bob": {Status: 200, Length: len(body)}}}
	dir := evidenceDir(t, evRow(t, row, ans("alice", "answer", u, 200, body, strings.Replace(curl, "BOB", "ALICE", 1)), ans("bob", "answer", u, 200, body, curl)))
	row.Dir = dir
	line, _ := json.Marshal(row)
	rolesFile = filepath.Join(t.TempDir(), "roles.jsonl")
	if err := os.WriteFile(rolesFile, append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return site, db, rep, rolesFile
}

// reportRecords are the records of `report -findings -db DB [-roles FILE]`, by kind.
func reportRecords(t *testing.T, db string, extra ...string) (byKind map[string][]map[string]any, errOut string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "f.jsonl")
	_, errOut, err := captureBoth(t, func() error {
		return cmdReport(append([]string{"-findings", "-db", db, "-format", "jsonl", "-o", out}, extra...))
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	raw, _ := os.ReadFile(out)
	byKind = map[string][]map[string]any{}
	for _, r := range jsonLines(t, string(raw)) {
		if r["type"] == "finding" {
			k, _ := r["kind"].(string)
			byKind[k] = append(byKind[k], r)
		}
	}
	return byKind, errOut
}

// huntFindings are the finding rows of `hunt -json`, by key.
func huntFindings(t *testing.T, db string, extra ...string) (rows map[string]map[string]any, findings int) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return cmdHunt(append([]string{"-db", db, "-json", "-limit", "500"}, extra...)) })
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	rows = map[string]map[string]any{}
	for _, r := range jsonLines(t, out) {
		if r["tier"] == "finding" {
			rows[fmt.Sprint(r["key"])+"|"+fmt.Sprint(r["reasons"].([]any)[0].(map[string]any)["signal"])] = r
		}
	}
	h := lastReport(t, errOut).Tiers
	if h == nil {
		t.Fatalf("hunt gave no tiers: %s", errOut)
	}
	return rows, h.Findings
}

// One workspace, one population of findings: a workspace holding every kind
// hunt proves gives the same count in the run's tiers, `hunt -json` and
// `report -findings`, and with the same -roles file in `hunt -roles`,
// `report -findings -roles` and `export -format findings -roles`.
func TestEveryKindHuntProvesIsAReportRecord(t *testing.T) {
	_, db, rep, rolesFile := everyKindWorkspace(t)
	kinds := []string{sqlErrorKind, debugPageKind, listingKind, gqlSchemaKind}
	recs, errOut := reportRecords(t, db)
	for _, k := range kinds {
		if len(recs[k]) != 1 {
			t.Errorf("report -findings holds %d %s records, want 1 (%v)", len(recs[k]), k, recs)
		}
	}
	total := 0
	for _, rs := range recs {
		total += len(rs)
	}
	if rep.Tiers == nil || rep.Tiers.Findings != total || total < len(kinds) {
		t.Errorf("run tiers %+v, report lists %d findings (%v)", rep.Tiers, total, errOut)
	}
	hrows, hn := huntFindings(t, db)
	if hn != total || len(hrows) != total {
		t.Errorf("hunt counts %d findings and lists %d, report -findings %d, run %+v", hn, len(hrows), total, rep.Tiers)
	}
	// The same rows: a hunt finding is a record, with its severity-free proof and command.
	for _, rs := range recs {
		for _, r := range rs {
			key := fmt.Sprint(r["url"]) + "|" + fmt.Sprint(r["kind"])
			h, ok := hrows[key]
			if !ok {
				t.Errorf("hunt has no finding row for the record %s", key)
				continue
			}
			if h["next"] != r["reproduce"] {
				t.Errorf("%s: hunt shows %q, the record reproduces with %q", key, h["next"], r["reproduce"])
			}
		}
	}
	// With the roles verdict.
	recs, _ = reportRecords(t, db, "-roles", rolesFile)
	if len(recs[crossRoleKind]) != 1 {
		t.Fatalf("report -findings -roles holds %d %s records: %v", len(recs[crossRoleKind]), crossRoleKind, recs)
	}
	_, hn = huntFindings(t, db, "-roles", rolesFile)
	if hn != total+1 {
		t.Errorf("hunt -roles counts %d findings, want %d", hn, total+1)
	}
	out, errOut, err := captureBoth(t, func() error {
		return cmdExport([]string{"-db", db, "-format", "findings", "-roles", rolesFile})
	})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range jsonLines(t, out) {
		if r["type"] == "finding" {
			n++
		}
	}
	if n != total+1 || !strings.Contains(errOut, fmt.Sprintf("%d findings", total+1)) {
		t.Errorf("export -format findings -roles: %d finding lines, headline %q", n, errOut)
	}
	// -roles is for the findings.
	if err := cmdReport([]string{"-dir", t.TempDir(), "-roles", rolesFile}); err == nil {
		t.Error("-roles without -findings is a usage error")
	}
}

func recordOf(t *testing.T, recs map[string][]map[string]any, kind string) map[string]any {
	t.Helper()
	if len(recs[kind]) != 1 {
		t.Fatalf("%d %s records: %v", len(recs[kind]), kind, recs)
	}
	return recs[kind][0]
}

// checkRecord holds what every record of a kind has: a finding with its tier,
// label, severity, request, command, and a proof with the stage, status, excerpt and reproduce.
func checkRecord(t *testing.T, r map[string]any, kind, severity, url, excerpt, status string) {
	t.Helper()
	if r["tier"] != "finding" || r["kind"] != kind || r["label"] != "proved" || r["severity"] != severity || r["url"] != url {
		t.Errorf("record %v: want a proved %s finding of severity %s at %s", r, kind, severity, url)
	}
	if ex, _ := r["excerpt"].(string); !strings.Contains(ex, excerpt) {
		t.Errorf("%s excerpt %q lacks %q", kind, ex, excerpt)
	}
	if fmt.Sprint(r["status"]) != status {
		t.Errorf("%s status %v, want %s", kind, r["status"], status)
	}
	for _, f := range []string{"observed_at", "method", "target", "excerpt_part", "how", "reproduce", "request", "evidence", "command"} {
		if s, _ := r[f].(string); s == "" {
			t.Errorf("%s record has no %s: %v", kind, f, r)
		}
	}
}

func TestSQLErrorTextIsAReportRecord(t *testing.T) {
	site, db, _, _ := everyKindWorkspace(t)
	recs, _ := reportRecords(t, db)
	r := recordOf(t, recs, sqlErrorKind)
	checkRecord(t, r, sqlErrorKind, "medium", site.URL+"/orders", "You have an error in your SQL syntax", "500")
	if rep, _ := r["reproduce"].(string); !strings.HasPrefix(rep, "curl -sS -i") || !strings.Contains(rep, site.URL+"/orders") {
		t.Errorf("reproduce %q", rep)
	}
	hrows, _ := huntFindings(t, db)
	h := hrows[site.URL+"/orders|"+sqlErrorKind]
	if h == nil || h["score"].(float64) != 50 || !strings.Contains(h["reasons"].([]any)[0].(map[string]any)["detail"].(string), "SQL syntax") {
		t.Errorf("hunt row %v", h)
	}
	for k, row := range hrows {
		if row["tier"] == "finding" && strings.HasPrefix(k, site.URL+"/orders|") && !strings.HasSuffix(k, "|"+sqlErrorKind) {
			t.Errorf("the route has a second finding row: %s", k)
		}
	}
}

func TestDebugPageIsAReportRecord(t *testing.T) {
	site, db, _, _ := everyKindWorkspace(t)
	recs, _ := reportRecords(t, db)
	r := recordOf(t, recs, debugPageKind)
	checkRecord(t, r, debugPageKind, "medium", site.URL+"/render", "Werkzeug Debugger", "500")
	hrows, _ := huntFindings(t, db)
	if h := hrows[site.URL+"/render|"+debugPageKind]; h == nil || h["score"].(float64) != 35 {
		t.Errorf("hunt row %v", h)
	}
}

func TestDirectoryListingIsAReportRecord(t *testing.T) {
	site, db, _, _ := everyKindWorkspace(t)
	recs, _ := reportRecords(t, db)
	r := recordOf(t, recs, listingKind)
	checkRecord(t, r, listingKind, "low", site.URL+"/files/", "title: Index of /files", "200")
	if r["content_type"] != "text/html" {
		t.Errorf("content type %v", r["content_type"])
	}
	hrows, _ := huntFindings(t, db)
	if h := hrows[site.URL+"/files/|"+listingKind]; h == nil || h["score"].(float64) != 55 {
		t.Errorf("hunt row %v", h)
	}
}

func TestGraphQLSchemaReadIsAReportRecord(t *testing.T) {
	site, db, _, _ := everyKindWorkspace(t)
	recs, _ := reportRecords(t, db)
	r := recordOf(t, recs, gqlSchemaKind)
	checkRecord(t, r, gqlSchemaKind, "low", site.URL+"/graphql", "queries me, pastes", "200")
	if r["method"] != "POST" || !strings.Contains(fmt.Sprint(r["request_bytes"]), "__schema") {
		t.Errorf("the request is a POST of the schema query: %v", r)
	}
	if rep, _ := r["reproduce"].(string); !strings.Contains(rep, "-X POST") || !strings.Contains(rep, "__schema") || !strings.Contains(rep, "Content-Type: application/json") {
		t.Errorf("reproduce %q", rep)
	}
	hrows, _ := huntFindings(t, db)
	if h := hrows[site.URL+"/graphql|"+gqlSchemaKind]; h == nil || h["score"].(float64) != 45 {
		t.Errorf("hunt row %v", h)
	}
}

func TestRolesVerdictIsAReportRecord(t *testing.T) {
	site, db, _, rolesFile := everyKindWorkspace(t)
	recs, _ := reportRecords(t, db, "-roles", rolesFile)
	r := recordOf(t, recs, crossRoleKind)
	u := site.URL + "/rest/basket/4711"
	checkRecord(t, r, crossRoleKind, "high", u, `"owner":"carol"`, "200")
	if r["how"] != "azhaq-roles" || !strings.Contains(fmt.Sprint(r["evidence"]), "bob read alice's basket") || !strings.Contains(fmt.Sprint(r["evidence"]), "(proved)") {
		t.Errorf("evidence %v how %v", r["evidence"], r["how"])
	}
	if rep, _ := r["reproduce"].(string); !strings.Contains(rep, "$BOB_TOKEN") || !strings.Contains(rep, u) {
		t.Errorf("the reproduce is the reader's request with its session as a variable: %q", rep)
	}
	if _, err := store.OpenEvidenceExisting(filepath.Join(filepath.Dir(rolesFile), evidenceFile)); err == nil {
		t.Error("the roles file's folder holds no evidence: the row's own dir is the one read")
	}
	hrows, hn := huntFindings(t, db, "-roles", rolesFile)
	h := hrows[u+"|"+crossRoleKind]
	if h == nil || h["score"].(float64) != float64(hunt.RoleRow{Verdict: verdictCross, Confidence: confProved}.Weight()) {
		t.Fatalf("hunt row %v", h)
	}
	if next, _ := h["next"].(string); !strings.HasPrefix(next, "azhaq roles show -dir ") || !strings.HasSuffix(next, u) {
		t.Errorf("hunt shows the roles run again: %q", next)
	}
	if recs, _ := reportRecords(t, db); len(recs[crossRoleKind]) != 0 {
		t.Error("without -roles there is no verdict to record")
	}
	// A verdict that is not proved is a lead of hunt's, not a finding of either.
	var row roleRow
	raw, _ := os.ReadFile(rolesFile)
	_ = json.Unmarshal(raw, &row)
	row.Confidence = confLikely
	line, _ := json.Marshal(row)
	likely := filepath.Join(t.TempDir(), "likely.jsonl")
	_ = os.WriteFile(likely, append(line, '\n'), 0o644)
	if _, n := huntFindings(t, db, "-roles", likely); n != hn-1 {
		t.Errorf("a likely verdict is no finding: hunt counts %d, want %d", n, hn-1)
	}
	if recs, _ := reportRecords(t, db, "-roles", likely); len(recs[crossRoleKind]) != 0 {
		t.Error("a likely verdict has no record")
	}
}
