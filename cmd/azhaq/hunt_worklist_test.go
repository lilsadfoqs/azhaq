package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/store"
)

// withStoredAdvisories puts the full advisory leads of the workspace, with the
// list of every advisory, in the report: the summary keeps one line for a
// lead, and the map keeps the list.
func withStoredAdvisories(t *testing.T, db string, rep report) report {
	t.Helper()
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs, err := st.Observations()
	if err != nil {
		t.Fatal(err)
	}
	var leads []advisory.Lead
	for _, o := range obs {
		var l advisory.Lead
		if o.Collector == "azhaq-advisories" && o.Kind == "advisory" && json.Unmarshal(o.Payload, &l) == nil {
			leads = append(leads, l)
		}
	}
	rep.Advisories = leads
	return rep
}

// The summary of a run with advisory leads stays small: one line a lead, not
// the whole advisory list of each.
func TestRunSummaryStaysSmallWithAdvisoryLeads(t *testing.T) {
	useBuiltinIndex(t)
	var seeds string
	for _, v := range []string{"2.4.49", "2.4.50", "2.4.51", "2.4.49"} {
		seeds += apacheServer(t, v).URL + "/\n"
	}
	list := filepath.Join(t.TempDir(), "seeds.txt")
	if err := os.WriteFile(list, []byte(seeds), 0o644); err != nil {
		t.Fatal(err)
	}
	egress.Reset()
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-list", list, "-db", db, "-json", "-depth", "0", "-no-paths", "-no-tech", "-no-favicon"})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	n := 0
	for _, l := range splitLines(errOut) {
		if len(l) > n && len(l) > 1 && l[0] == '{' {
			n = len(l)
		}
	}
	t.Logf("summary bytes: %d", n)
	if n > 32<<10 {
		t.Errorf("summary is %d bytes, want at most 32 KB", n)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// expressServer names a product and no version, as a port scan reads it.
func expressServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		fmt.Fprint(w, "hi")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func labPortOf(srv *httptest.Server) string {
	return strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
}

// worklist runs a lab of routes (a Juice Shop shaped app) and three listeners
// on loopback into one workspace: Apache 2.4.49, ProFTPD 1.3.5 and Express
// with no version. It returns the workspace and the run's stderr.
func worklist(t *testing.T, extra ...string) (db, errOut string) {
	t.Helper()
	useBuiltinIndex(t)
	var hits atomic.Int64
	shop := juiceShaped(&hits)
	t.Cleanup(shop.Close)
	db = filepath.Join(t.TempDir(), "w.db")
	ports := labPortOf(apacheServer(t, "2.4.49")) + "," + strconv.Itoa(ftpServer(t, "1.3.5")) + "," + labPortOf(expressServer(t))
	args := append([]string{"run", "-url", shop.URL + "/", "-cidr", "127.0.0.1/32", "-ports", ports, "-allow", "127.0.0.1", "-sources", "none", "-depth", "1", "-no-favicon", "-db", db}, extra...)
	_, errOut, code := cli(t, args...)
	if code != exitOK {
		t.Fatalf("run: exit %d\n%s", code, errOut)
	}
	return db, errOut
}

// huntJSON is the rows `azhaq hunt -json` printed, and its summary.
func huntJSON(t *testing.T, db string, extra ...string) ([]map[string]any, map[string]any) {
	t.Helper()
	out, errOut, err := captureBoth(t, func() error { return cmdHunt(append([]string{"-db", db, "-json"}, extra...)) })
	if err != nil {
		t.Fatalf("hunt: %v\n%s", err, errOut)
	}
	var rows []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		rows = append(rows, m)
	}
	return rows, sumMap(t, errOut)
}

func identsOf(rows []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range rows {
		if r["kind"] == "identification" {
			out = append(out, r)
		}
	}
	return out
}

// hunt lists what the run named on each listener beside the routes and hosts:
// the product, the version or "no version seen", the top advisory with its
// label, the proof excerpt and the command that reproduces it.
func TestHuntListsIdentificationsBesideRoutes(t *testing.T) {
	db, _ := worklist(t)
	out, errOut, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-limit", "100"}) })
	if err != nil {
		t.Fatalf("hunt: %v\n%s", err, errOut)
	}
	for _, want := range []string{
		"identifications (3)",
		"Apache httpd 2.4.49", "CVE-2021-41773 version-only", "known exploited (CISA KEV)",
		"proof: Apache/2.4.49", "curl -sS",
		"ProFTPD 1.3.5", "CVE-2015-3306 version-only", "nc -w 3 127.0.0.1",
		"Express (no version seen)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hunt text lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "/rest/") {
		t.Errorf("hunt text has no route beside the listeners:\n%s", out)
	}
	if !strings.Contains(errOut, "identifications") {
		t.Errorf("the summary does not count the identifications:\n%s", errOut)
	}

	rows, sum := huntJSON(t, db, "-limit", "100")
	ids := identsOf(rows)
	if len(ids) != 3 {
		t.Fatalf("%d identification rows, want 3 (Apache, ProFTPD, Express):\n%v", len(ids), rows)
	}
	var apache, express map[string]any
	for _, r := range ids {
		switch r["product"] {
		case "Apache httpd":
			apache = r
		case "Express":
			express = r
		}
	}
	if apache == nil || express == nil {
		t.Fatalf("identification rows %v", ids)
	}
	if apache["tier"] != "identification" || apache["version"] != "2.4.49" || apache["advisory_id"] != "CVE-2021-41773" || apache["label"] != "version-only" ||
		apache["severity"] == "" || apache["host"] != "127.0.0.1" || apache["port"] == nil || apache["evidence"] == "" || apache["command"] == nil || apache["type"] != "Service" {
		t.Errorf("Apache row %v", apache)
	}
	if p, _ := apache["proof"].(map[string]any); p == nil || !strings.Contains(fmt.Sprint(p["excerpt"]), "Apache/2.4.49") || !strings.HasPrefix(fmt.Sprint(p["reproduce"]), "curl ") {
		t.Errorf("Apache proof %v", apache["proof"])
	}
	if n, _ := apache["advisories"].(float64); n < 50 {
		t.Errorf("Apache row counts %v advisories", apache["advisories"])
	}
	if express["version"] != "" || express["advisory_id"] != nil || !strings.Contains(fmt.Sprint(express["evidence"]), "no version seen") {
		t.Errorf("Express row %v: want no version seen and no advisory", express)
	}
	if tiers, _ := sum["tiers"].(map[string]any); tiers == nil || tiers["identifications"] != float64(3) {
		t.Errorf("summary tiers %v", sum["tiers"])
	}
	if routes := len(rows) - len(ids); routes == 0 {
		t.Errorf("no route among the rows: %v", rows)
	}
}

// Findings first, then identifications (a version seen before none), then leads.
func TestHuntOrdersByTier(t *testing.T) {
	db, _ := worklist(t)
	rows, _ := huntJSON(t, db, "-limit", "1000")
	rank := func(r map[string]any) int {
		switch r["tier"] {
		case "finding":
			return 0
		case "identification":
			if r["version"] == "" {
				return 2
			}
			return 1
		}
		return 3
	}
	last, seen := -1, map[int]bool{}
	for _, r := range rows {
		k := rank(r)
		seen[k] = true
		if k < last {
			t.Fatalf("row %v (tier rank %d) follows a row of rank %d", r["key"], k, last)
		}
		last = k
	}
	if !seen[1] || !seen[2] || !seen[3] {
		t.Errorf("the lab lacks a tier: %v", seen)
	}
}

// `report -findings` and `hunt` say the same of every listener: the same
// product, version, top advisory and label, one hunt row for each listener.
func TestHuntAndReportFindingsAgreeOnIdentifications(t *testing.T) {
	db, _ := worklist(t)
	var buf bytes.Buffer
	if err := exportAs(db, "findings", "", &buf); err != nil {
		t.Fatal(err)
	}
	_, idents, _ := parseTiers(t, buf.Bytes())
	top := map[string]map[string]any{} // host:port|product → the report's first record
	for _, r := range idents {
		k := fmt.Sprintf("%v:%v|%v", r["host"], r["port"], r["product"])
		if _, ok := top[k]; !ok {
			top[k] = r
		}
	}
	rows, _ := huntRowsJSON(t, db)
	got := identsOf(rows)
	if len(got) != len(top) || len(got) == 0 {
		t.Fatalf("hunt has %d identification rows, the report's records are for %d listeners", len(got), len(top))
	}
	for _, r := range got {
		k := fmt.Sprintf("%v:%v|%v", r["host"], r["port"], r["product"])
		rec := top[k]
		if rec == nil {
			t.Errorf("hunt row %s is not in the report", k)
			continue
		}
		for _, f := range []string{"version", "advisory_id", "label", "severity"} {
			if fmt.Sprint(r[f]) != fmt.Sprint(rec[f]) && !(r[f] == "" && rec[f] == nil) && !(r[f] == nil && rec[f] == "") {
				t.Errorf("%s: hunt says %s %v, the report %v", k, f, r[f], rec[f])
			}
		}
	}
}

func huntRowsJSON(t *testing.T, db string) ([]map[string]any, map[string]any) {
	return huntJSON(t, db, "-limit", "1000")
}

// -limit caps the rows; the summary counts the three tiers apart, says how
// many the limit left out and the flag that shows them.
func TestHuntLimitSaysWhatItLeftOut(t *testing.T) {
	db, _ := worklist(t)
	all, _ := huntJSON(t, db, "-limit", "1000")
	rows, sum := huntJSON(t, db, "-limit", "2")
	if len(rows) != 2 {
		t.Fatalf("%d rows with -limit 2", len(rows))
	}
	notes := fmt.Sprint(sum["notes"])
	for _, want := range []string{fmt.Sprintf("%d rows have a signal", len(all)), fmt.Sprintf("%d are left out", len(all)-2), fmt.Sprintf("-limit %d prints them all", len(all)), "3 identifications", "leads"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes %q lack %q", notes, want)
		}
	}
}

// Every run that stored rows names hunt first, with the counts hunt would
// show, in the JSON summary and in the text, whatever stderr is.
func TestRunNamesHuntFirstWithCounts(t *testing.T) {
	prev := hintTerminal
	hintTerminal = func() bool { return false }
	defer func() { hintTerminal = prev }()
	db, textErr := worklist(t)
	rows, _ := huntJSON(t, db, "-limit", "1000")
	var f, i, l int
	for _, r := range rows {
		switch r["tier"] {
		case "finding":
			f++
		case "identification":
			i++
		default:
			l++
		}
	}
	want := fmt.Sprintf("azhaq hunt -db %s   (%s, %s, %s)", db, plural(f, "finding"), plural(i, "identification"), plural(l, "lead"))
	var first string
	for _, line := range strings.Split(textErr, "\n") {
		if strings.HasPrefix(line, "  next: ") {
			first = strings.TrimPrefix(line, "  next: ")
			break
		}
	}
	if first != want {
		t.Errorf("the first next line of the text summary is %q, want %q", first, want)
	}

	// The same in JSON, with stderr not a terminal.
	var hits atomic.Int64
	shop := juiceShaped(&hits)
	defer shop.Close()
	db2 := filepath.Join(t.TempDir(), "j.db")
	sum := runJSON(t, "run", "-url", shop.URL+"/", "-allow", "127.0.0.1", "-sources", "none", "-db", db2)
	next, _ := sum["next"].([]any)
	if len(next) == 0 || !strings.HasPrefix(fmt.Sprint(next[0]), "azhaq hunt -db "+db2+"   (") || !strings.HasSuffix(fmt.Sprint(next[0]), " leads)") {
		t.Errorf("the JSON summary's first next is %v", next)
	}
	hr, _ := huntJSON(t, db2, "-limit", "1000")
	tiers := map[string]int{}
	for _, r := range hr {
		tiers[fmt.Sprint(r["tier"])]++
	}
	if w := fmt.Sprintf("(%s, %s, %s)", plural(tiers["finding"], "finding"), plural(tiers["identification"], "identification"), plural(tiers["lead"], "lead")); !strings.Contains(fmt.Sprint(next[0]), w) {
		t.Errorf("next %v does not count what hunt shows: %s", next[0], w)
	}
}

// A listener gets one row for each product, from its best record with the count
// of its advisories; a finding a read proved is a finding row; the findings of
// other collectors (a secret, a path) are not listener rows.
func TestListenersOfTakesOneRowForEachProduct(t *testing.T) {
	set := findingSet{
		Findings: []findingRecord{
			{Tier: "finding", Kind: "unauthenticated-read", Label: "proved", Severity: "info", Host: "10.0.0.5", Port: 6379, Product: "Redis", Collector: "azhaq-verify"},
			{Tier: "finding", Kind: "secret", Label: "proved", Host: "10.0.0.5", Collector: "azhaq-js"},
		},
		Identifications: []findingRecord{
			{Tier: "identification", Kind: "advisory-precondition", Label: "proved", Host: "10.0.0.5", Port: 8161, Product: "ActiveMQ", Version: "5.15.0", AdvisoryID: "CVE-1"},
			{Tier: "identification", Kind: "advisory-precondition", Label: "version-only", Host: "10.0.0.5", Port: 8161, Product: "ActiveMQ", Version: "5.15.0", AdvisoryID: "CVE-2"},
			{Tier: "identification", Kind: "software-version", Label: "version-only", Host: "10.0.0.5", Port: 22, Product: "OpenSSH"},
		},
	}
	got := listenersOf(set)
	if len(got) != 3 {
		t.Fatalf("%d listener rows, want 3: %+v", len(got), got)
	}
	if got[0].Kind != "finding" || got[0].Port != 6379 || got[1].AdvisoryID != "CVE-1" || got[1].Label != "proved" || got[1].Advisories != 2 || got[2].Version != "" || got[2].Advisories != 0 {
		t.Errorf("%+v", got)
	}
}
