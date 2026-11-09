package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// evidenceDir is a roles run's directory holding the rows, and the names of its roles.
func evidenceDir(t *testing.T, rows ...store.EvidenceRow) string {
	t.Helper()
	dir := t.TempDir()
	ev, err := store.OpenEvidence(filepath.Join(dir, evidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Save([]string{"alice", "bob"}, rows); err != nil {
		t.Fatal(err)
	}
	ev.Close()
	return dir
}

// A row gets a report when its verdict is one of the seven listed; a -url
// whose row is none of them, or that matches no row, is exit 1; report sends
// nothing.
func TestReportSevenVerdictsAndNothingSent(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	seven := []string{
		"reads another role's object",
		"writes another role's object",
		"writes another role's object: accepted; the change cannot be read back to confirm",
		"anyone writes another role's object",
		"creates in another role's collection",
		"create accepted: nothing shows it crosses roles",
		"anyone reads sensitive fields",
	}
	classes := map[string]bool{}
	for _, v := range seven {
		c, _ := classOf(v)
		if c == "" {
			t.Errorf("%q gets no report", v)
		}
		classes[c] = true
	}
	if _, label := classOf(verdictWriteUnread); label != "Broken object level authorization (write accepted, not read back)" {
		t.Errorf("a write that could not be read back is titled %q", label)
	}
	for _, v := range []string{verdictAnyID, verdictObject, verdictSignedIn, verdictWriteNoChange, verdictPublicObj, ""} {
		if c, _ := classOf(v); c != "" {
			t.Errorf("%q gets a report (class %q)", v, c)
		}
	}
	quiet := roleRow{URL: "https://shop.example.test:8443/me", Verdict: verdictSignedIn, Answers: map[string]answer{}}
	dir := evidenceDir(t, basketRow(t), evRow(t, quiet))
	before := egress.Sent()
	for name, args := range map[string][]string{
		"a verdict that gets no report": {"-dir", dir, "-url", "https://shop.example.test:8443/me"},
		"a url that matches no row":     {"-dir", dir, "-url", "https://shop.example.test:8443/nothing"},
	} {
		if _, _, err := captureBoth(t, func() error { return cmdReport(args) }); exitCode(err) != exitError {
			t.Errorf("%s: exit %d (%v), want 1", name, exitCode(err), err)
		}
	}
	if _, _, err := captureBoth(t, func() error { return cmdReport([]string{"-dir", dir, "-o", filepath.Join(dir, "out") + "/"}) }); err != nil {
		t.Fatal(err)
	}
	if got := egress.Sent() - before; got != 0 {
		t.Errorf("report sent %d requests", got)
	}
}

// When no row qualifies, report prints a note on stderr, writes nothing and exits 0.
func TestReportWhenNoRowQualifiesWritesNothingAndExits0(t *testing.T) {
	quiet := roleRow{URL: "https://shop.example.test/me", Verdict: verdictSignedIn, Answers: map[string]answer{}}
	dir := evidenceDir(t, evRow(t, quiet))
	out, errOut, err := captureBoth(t, func() error { return cmdReport([]string{"-dir", dir}) })
	if err != nil || out != "" || !strings.Contains(errOut, "azhaq report: no row in ") {
		t.Errorf("exit %d (%v), stdout %q, stderr %q", exitCode(err), err, out, errOut)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "reports", "*")); len(files) != 0 {
		t.Errorf("files written: %v", files)
	}
}

// Without -url the reports go to DIR/reports, one file each, and stdout lists
// them; -o picks another place; with -url one report goes to standard output,
// but several rows of one URL and method go to DIR/reports (or -o).
func TestReportWhereTheReportsGo(t *testing.T) {
	const u = "https://shop.example.test/books"
	mk := func(owner, reader string) store.EvidenceRow {
		er := evRow(t, roleRow{URL: u, Method: "POST", Owner: owner, Readers: []string{reader}, Verdict: verdictWriteAccepted, Answers: map[string]answer{}},
			ans(reader, "answer", u, 200, `{"by":"`+reader+`"}`, "curl -X POST '"+u+"'"))
		er.Owner = owner
		return er
	}
	dir := evidenceDir(t, basketRow(t), mk("alice", "bob"), mk("bob", "alice"))
	out, _, err := captureBoth(t, func() error { return cmdReport([]string{"-dir", dir}) })
	files, _ := filepath.Glob(filepath.Join(dir, "reports", "*.md"))
	if err != nil || len(files) != 3 || !strings.Contains(out, "3 reports in "+filepath.Join(dir, "reports")) {
		t.Fatalf("files %v, stdout %q (%v): want one file for each of the 3 in DIR/reports, listed on stdout", files, out, err)
	}
	for _, f := range files {
		if !strings.Contains(out, filepath.Base(f)) {
			t.Errorf("stdout does not list %s:\n%s", filepath.Base(f), out)
		}
	}
	// One row by -url: the report is the standard output, and no file is written.
	only := evidenceDir(t, basketRow(t))
	out, _, err = captureBoth(t, func() error {
		return cmdReport([]string{"-dir", only, "-url", "https://shop.example.test:8443/rest/basket/4711"})
	})
	if err != nil || !strings.HasPrefix(out, "# Broken object level authorization") {
		t.Errorf("one report with -url: %q (%v)", out, err)
	}
	if files, _ := filepath.Glob(filepath.Join(only, "reports", "*")); len(files) != 0 {
		t.Errorf("-url with one row wrote %v", files)
	}
	// Two rows of one URL and method: DIR/reports, not standard output.
	before, _ := filepath.Glob(filepath.Join(dir, "reports", "*"))
	for _, f := range before {
		os.Remove(f)
	}
	out, _, err = captureBoth(t, func() error { return cmdReport([]string{"-dir", dir, "-url", u, "-method", "POST"}) })
	files, _ = filepath.Glob(filepath.Join(dir, "reports", "*.md"))
	if err != nil || len(files) != 2 || strings.Contains(out, "# Create accepted") || !strings.Contains(out, "2 reports") {
		t.Errorf("-url matching two owners: %d files, stdout %q (%v)", len(files), out, err)
	}
	// -o picks another place.
	other := filepath.Join(dir, "elsewhere") + "/"
	if _, _, err := captureBoth(t, func() error { return cmdReport([]string{"-dir", dir, "-o", other}) }); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "elsewhere", "*.md")); len(files) != 3 {
		t.Errorf("-o: %v", files)
	}
}

// A create that was not read back says so, and a create's report gives no
// confidence: unrated.
func TestReportOfACreateIsUnratedAndSaysItWasNotReadBack(t *testing.T) {
	const u = "https://s.test/books/v1"
	row := roleRow{URL: u, Method: "POST", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictWriteAccepted, Answers: map[string]answer{}}
	d, err := buildReport(evRow(t, row, ans("bob", "answer", u, 200, `{"ok":true}`, "curl -X POST '"+u+"'")), []string{"alice", "bob"}, time.Date(2026, 10, 29, 9, 30, 0, 0, time.UTC), true, false)
	if err != nil {
		t.Fatal(err)
	}
	md := d.markdown()
	if d.Confidence != "unrated" {
		t.Errorf("confidence %q:\n%s", d.Confidence, md)
	}
	if !strings.Contains(strings.ToLower(md), "read back") {
		t.Errorf("the report does not say the create was not read back:\n%s", md)
	}
}

// An identifier no kept body names in an identifier field is not masked.
func TestReportRedactLeavesAnIdentifierNoBodyNamesInAnIdentifierField(t *testing.T) {
	const host = "https://shop.example.test"
	u := host + "/rest/basket/4711"
	body := `{"id":4711,"reference":"RX-99231"}`
	row := roleRow{URL: u, From: host + "/rest/basket/{id}", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, Confidence: confProved,
		Answers: map[string]answer{"alice": {Status: 200, Length: len(body)}, "bob": {Status: 200, Length: len(body)}}}
	d, err := buildReport(evRow(t, row, ans("alice", "answer", u, 200, body, "curl '"+u+"'"), ans("bob", "answer", u, 200, body, "curl '"+u+"'")),
		[]string{"alice", "bob"}, time.Date(2026, 10, 29, 9, 30, 0, 0, time.UTC), true, true)
	if err != nil {
		t.Fatal(err)
	}
	md := d.markdown()
	if strings.Contains(md, "4711") || strings.Contains(md, "shop.example.test") {
		t.Errorf("an identifier or the host was kept:\n%s", md)
	}
	if !strings.Contains(md, "RX-99231") {
		t.Errorf("a value in a field that is not an identifier was masked:\n%s", md)
	}
}

// report -findings sends nothing; -format json is jsonl; the labels in the
// Markdown headings count the records under them.
func TestReportFindingsSendsNothingAndJSONIsJSONL(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	db := exportDB(t, t.TempDir())
	before := egress.Sent()
	jsonl, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl"}) })
	if err != nil {
		t.Fatal(err)
	}
	asJSON, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "json"}) })
	if err != nil || asJSON != jsonl || strings.TrimSpace(jsonl) != `{"type":"findings","findings":0,"leads":0}` {
		t.Errorf("-format json %q, jsonl %q (%v)", asJSON, jsonl, err)
	}
	if _, _, err := captureBoth(t, func() error { return cmdReport([]string{"-findings", "-db", db, "-format", "md"}) }); err != nil {
		t.Fatal(err)
	}
	if got := egress.Sent() - before; got != 0 {
		t.Errorf("report -findings sent %d requests", got)
	}
}

// Rows that prove nothing (a map row whose coverage is hint) are leads, after
// the findings, with their own type in JSONL and their own heading in Markdown.
func TestFindingsLeadsHaveTheirOwnTypeAndHeading(t *testing.T) {
	g := &graphView{args: []string{"-url", "http://app.test/"}, rows: []engine.MapEntry{
		{Entity: types.Entity{Type: types.TypeURL, Key: "http://app.test/api/things"}, Coverage: "hint", Proof: "GET answers 404; called with POST"},
	}}
	found, leads, folds := buildFindings(g)
	if len(found) != 0 || len(leads) != 1 {
		t.Fatalf("%d findings, %d leads", len(found), len(leads))
	}
	if !strings.Contains(string(findingsJSONL(found, leads, folds)), `"type":"lead"`) {
		t.Errorf("jsonl: %s", findingsJSONL(found, leads, folds))
	}
	if md := string(findingsMarkdown(found, leads, folds)); !strings.Contains(md, "## Leads — unproved hints") || strings.Contains(md, "## Proved") {
		t.Errorf("markdown:\n%s", md)
	}
}
