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
	"time"

	"github.com/lilsadfoqs/azhaq/store"
)

const reportJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYXJvbCJ9.c2lnbmF0dXJlMTIz"

// evRow is a listed row with the answers behind it, as roles saves them.
func evRow(t *testing.T, row roleRow, answers ...store.EvidenceAnswer) store.EvidenceRow {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return store.EvidenceRow{URL: row.URL, Method: row.Method, Row: raw, Answers: answers}
}

func ans(role, kind, asked string, status int, body string, curl string) store.EvidenceAnswer {
	a := store.EvidenceAnswer{Role: role, Kind: kind, Asked: asked, Status: status, Length: len(body), ContentType: "application/json", Curl: curl}
	if body != "" {
		a.Body = []byte(body)
	}
	return a
}

// basketRow is bob reading alice's basket on a shop with a host, a port and
// numeric identifiers.
func basketRow(t *testing.T) store.EvidenceRow {
	const host = "https://shop.example.test:8443"
	body := `{"id":4711,"UserId":"carol@x.test","owner":"carol","Products":[{"name":"Juice","token":"` + reportJWT + `"}]}`
	row := roleRow{
		URL: host + "/rest/basket/4711", From: host + "/rest/basket/{id}", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, Confidence: confProved,
		OwnerBy: "bid claim of alice's token → " + host + "/rest/basket/4711 holds carol@x.test", Sensitive: []string{"token"}, BothWays: true,
		Answers: map[string]answer{"alice": {Status: 200, Length: len(body), Hash: "h1"}, "bob": {Status: 200, Length: len(body), Hash: "h1"}},
		Control: &control{URL: host + "/rest/basket/1000003", Value: "1000003", Answers: map[string]answer{"bob": {Status: 404, Length: 9}}},
	}
	get := func(who, name, u string) string {
		return "curl -sS -i '" + u + "' -H \"Authorization: Bearer $" + name + "_TOKEN\""
	}
	u := host + "/rest/basket/4711"
	return evRow(t, row,
		ans("alice", "answer", u, 200, body, get("alice", "ALICE", u)),
		ans("bob", "answer", u, 200, body, get("bob", "BOB", u)),
		ans("bob", "control", host+"/rest/basket/1000003", 404, `{"error":"not found"}`, get("bob", "BOB", host+"/rest/basket/1000003")))
}

func TestReportClassAndTitle(t *testing.T) {
	for _, c := range []struct {
		verdict, class, title string
		readers               []string
	}{
		{verdictCross, classRead, "Broken object level authorization: bob reads alice's basket via GET /rest/basket/{id}", []string{"bob"}},
		{verdictCross, classRead, "Broken object level authorization: bob and carol read alice's basket via GET /rest/basket/{id}", []string{"bob", "carol"}},
		{verdictWriteCross, classWrite, "Broken object level authorization (write): bob writes alice's basket via GET /rest/basket/{id}", []string{"bob"}},
		{verdictWriteAnyone, classWrite, "Broken object level authorization (write): anyone writes alice's basket via GET /rest/basket/{id}", []string{"anon", "bob"}},
		{verdictWriteCreate, classCreate, "Missing authorization on create: bob creates in alice's basket collection via GET /rest/basket/{id}", []string{"bob"}},
		{verdictAnyoneSecrets, classExposure, "Excessive data exposure: anyone reads password and token via GET /rest/basket/{id}", nil},
		{verdictSecrets, classExposure, "Excessive data exposure to signed-in roles: alice and bob read the same password and token via GET /rest/basket/{id}", []string{"alice", "bob"}},
	} {
		row := roleRow{URL: "https://s.test/rest/basket/6", From: "https://s.test/rest/basket/{id}", Owner: "alice", Readers: c.readers, Verdict: c.verdict, Confidence: confLikely, Sensitive: []string{"password", "token"},
			Answers: map[string]answer{}}
		d, err := buildReport(evRow(t, row), nil, time.Time{}, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if d.Class != c.class || d.Title != c.title {
			t.Errorf("%s: class %q title %q, want %q %q", c.verdict, d.Class, d.Title, c.class, c.title)
		}
	}
	// The same secrets several signed-in roles read: not said to be anyone's, and lower to start.
	shared := roleRow{URL: "https://s.test/users/v1/_debug", Readers: []string{"alice", "bob"}, Verdict: verdictSecrets, Sensitive: []string{"password"}, Answers: map[string]answer{}}
	d, err := buildReport(evRow(t, shared), nil, time.Time{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Summary+d.Impact, "anyone") || strings.Contains(d.Summary+d.Impact, "anonymous") || !strings.Contains(d.Impact, "Several signed-in accounts") {
		t.Errorf("summary %q\nimpact %q", d.Summary, d.Impact)
	}
	if anyone := severityOf(roleRow{Verdict: verdictAnyoneSecrets, Sensitive: []string{"password"}}, classExposure, false); d.Severity.Level == anyone.Level {
		t.Errorf("shared secrets rank %s, as secrets anyone reads do", d.Severity.Level)
	}
	// A verdict that is not a cross-role read or write has no report.
	for _, v := range []string{verdictAnyID, verdictObject, verdictSignedIn, verdictWriteNoChange, verdictPublicObj} {
		if c, _ := classOf(v); c != "" {
			t.Errorf("%q is class %q", v, c)
		}
		if _, err := buildReport(evRow(t, roleRow{URL: "https://s.test/x", Verdict: v}), nil, time.Time{}, false, false); err == nil {
			t.Errorf("a report was built for %q", v)
		}
	}
}

func TestReportNoun(t *testing.T) {
	for route, want := range map[string]string{
		"/rest/basket/{id}": "basket", "/books/v1/{book_title}": "book", "/api/v2/categories/{id}": "category",
		"/api/{id}": "object", "/users/v1/{username}/email": "email", "/orders/<id-1>": "order",
	} {
		if got := noun(route); got != want {
			t.Errorf("noun(%s) = %q, want %q", route, got, want)
		}
	}
}

func TestReportSeverityIsAGuessThatSensitiveFieldsAndWritesRaise(t *testing.T) {
	read := severityOf(roleRow{Verdict: verdictCross}, classRead, false)
	readSens := severityOf(roleRow{Verdict: verdictCross, Sensitive: []string{"secret"}}, classRead, false)
	write := severityOf(roleRow{Verdict: verdictWriteCross}, classWrite, false)
	anon := severityOf(roleRow{Verdict: verdictWriteAnyone}, classWrite, false)
	if read.Level != "medium" || readSens.Level != "high" || write.Level != "high" || anon.Level != "critical" {
		t.Errorf("levels %s %s %s %s", read.Level, readSens.Level, write.Level, anon.Level)
	}
	if !strings.Contains(readSens.Reason, "secret") || !strings.Contains(write.Reason, "write") {
		t.Errorf("reasons %q / %q", readSens.Reason, write.Reason)
	}
	d, err := buildReport(basketRow(t), []string{"alice", "bob"}, time.Time{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.markdown(), "## Severity (a guess)") {
		t.Error("the severity is not labelled a guess")
	}
}

func TestReportFullRow(t *testing.T) {
	saved := time.Date(2026, 10, 29, 9, 30, 0, 0, time.UTC)
	d, err := buildReport(basketRow(t), []string{"alice", "bob"}, saved, true, false)
	if err != nil {
		t.Fatal(err)
	}
	md := d.markdown()
	for _, want := range []string{
		"# Broken object level authorization: bob reads alice's basket via GET /rest/basket/{id}",
		"## Summary", "## Severity (a guess)", "## Steps to reproduce", "## Evidence", "## Why the object is the owner's", "## Impact", "## Remediation", "## Notes",
		`-H "Authorization: Bearer $BOB_TOKEN"`, "ALICE_TOKEN and BOB_TOKEN", "> bid claim of alice's token", "Both ways: yes",
		"Found by azhaq roles, run 2026-10-29 09:30 UTC", "Control: bob, a made-up identifier", "Expected: 404",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the report lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "Missing from the evidence store") {
		t.Errorf("a complete row reports something missing:\n%s", md)
	}
	if strings.Contains(md, "Co-Authored") || strings.Contains(md, "Bearer eyJ") {
		t.Error("a credential or an attribution in the report")
	}
}

func TestReportSaysWhatTheEvidenceLacks(t *testing.T) {
	const u = "https://s.test/api/notes/7"
	row := roleRow{URL: u, From: "https://s.test/api/notes/{id}", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, Confidence: confGuess,
		Answers: map[string]answer{"alice": {Status: 200, Length: 120}, "bob": {Status: 200, Length: 120}}}
	er := evRow(t, row,
		ans("alice", "answer", u, 200, `{"id":7}`, "curl -sS -i '"+u+"' -H \"Authorization: Bearer $ALICE_TOKEN\""),
		store.EvidenceAnswer{Role: "bob", Kind: "answer", Asked: u, Status: 200, Length: 120, Curl: "curl -sS -i '" + u + "' -H \"Authorization: Bearer $BOB_TOKEN\""})
	d, err := buildReport(er, []string{"alice", "bob"}, time.Time{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	md := d.markdown()
	for _, want := range []string{
		"No control was asked for this row",
		"The body was not kept: only its status and length are in the evidence store.",
		"The row holds no reason why the object is the owner's.",
		"the run date is not recorded in this evidence store",
		"the body bob got (120 bytes) was not kept",
		"Confidence: guess",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the report lacks %q:\n%s", want, md)
		}
	}
	// The same words in the JSON, as a list.
	var js map[string]any
	raw, _ := json.Marshal(d)
	if err := json.Unmarshal(raw, &js); err != nil || len(js["missing"].([]any)) < 3 {
		t.Errorf("json missing: %v %v", js["missing"], err)
	}
}

func TestReportRedactMasksHostsIdentifiersAndTokens(t *testing.T) {
	d, err := buildReport(basketRow(t), []string{"alice", "bob"}, time.Time{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	var raw strings.Builder
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(d)
	for name, out := range map[string]string{"markdown": d.markdown(), "json": raw.String()} {
		for _, leak := range []string{"shop.example.test", "8443", "4711", "carol", "1000003", "eyJ", reportJWT} {
			if strings.Contains(out, leak) {
				t.Errorf("%s keeps %q:\n%s", name, leak, out)
			}
		}
		for _, keep := range []string{"<host>", "<id-1>", "alice", "bob", "{id}"} {
			if !strings.Contains(out, keep) {
				t.Errorf("%s lost %q", name, keep)
			}
		}
	}
	// Without -redact the same report names them.
	plain, _ := buildReport(basketRow(t), []string{"alice", "bob"}, time.Time{}, false, false)
	if !strings.Contains(plain.markdown(), "shop.example.test:8443/rest/basket/4711") {
		t.Error("an unredacted report lost the host")
	}
}

func TestReportRedactWithoutATemplateMasksIdSegments(t *testing.T) {
	row := roleRow{URL: "https://s.test/rest/basket/6", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictCross, Confidence: confLikely, Answers: map[string]answer{}}
	d, err := buildReport(evRow(t, row), nil, time.Time{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if d.Route != "/rest/basket/{id}" || strings.Contains(d.markdown(), "basket/6") {
		t.Errorf("route %q:\n%s", d.Route, d.markdown())
	}
}

func TestReportOrderIsProvedLikelyGuessThenUnrated(t *testing.T) {
	ds := []reportDoc{{URL: "d", Confidence: "unrated", Verdict: verdictAnyoneSecrets}, {URL: "c", Confidence: confGuess, Verdict: verdictCross},
		{URL: "b", Confidence: confLikely, Verdict: verdictCross}, {URL: "a", Confidence: confProved, Verdict: verdictCross}}
	sortReports(ds)
	var got string
	for _, d := range ds {
		got += d.URL
	}
	if got != "abcd" {
		t.Errorf("order %q", got)
	}
}

// cmdReport on an evidence database: one file per finding, none for the
// rows that are not findings, -url refusing a row that is not one.
func TestReportCommand(t *testing.T) {
	dir := t.TempDir()
	ev, err := store.OpenEvidence(filepath.Join(dir, evidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	quiet := roleRow{URL: "https://shop.example.test:8443/me", Verdict: verdictSignedIn, Answers: map[string]answer{}}
	if err := ev.Save([]string{"alice", "bob"}, []store.EvidenceRow{basketRow(t), evRow(t, quiet)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ev.SavedAt(); !ok {
		t.Error("the evidence holds no run date")
	}
	ev.Close()

	out := filepath.Join(dir, "out")
	if err := cmdReport([]string{"-dir", dir, "-o", out + "/"}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.md"))
	if len(files) != 1 || !strings.Contains(files[0], "01-proved-get-rest-basket-id") {
		t.Fatalf("files %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), "bob reads alice's basket") || !strings.Contains(string(b), "run 20") {
		t.Errorf("report:\n%s", b)
	}

	if err := cmdReport([]string{"-dir", dir, "-url", "https://shop.example.test:8443/me"}); err == nil {
		t.Error("a signed-in-only row was written up")
	}
	if err := cmdReport([]string{"-dir", dir, "-url", "https://shop.example.test:8443/nothing"}); err == nil {
		t.Error("a row that does not exist was written up")
	}
	js := filepath.Join(dir, "r.json")
	if err := cmdReport([]string{"-dir", dir, "-url", "https://shop.example.test:8443/rest/basket/4711", "-format", "json", "-o", js, "-redact"}); err != nil {
		t.Fatal(err)
	}
	var d reportDoc
	b, _ = os.ReadFile(js)
	if err := json.Unmarshal(b, &d); err != nil || d.Class != classRead || strings.Contains(string(b), "shop.example.test") {
		t.Errorf("json %v:\n%s", err, b)
	}
	if err := cmdReport([]string{"-dir", dir, "-format", "xml"}); err == nil {
		t.Error("-format xml accepted")
	}
}

func TestReportWrite(t *testing.T) {
	const u = "https://s.test/api/items/3"
	row := roleRow{URL: u, Method: "PUT", From: "https://s.test/api/items/{id}", Owner: "alice", Readers: []string{"bob"}, Verdict: verdictWriteCross, Confidence: confProved,
		OwnerBy: "alice.har; after bob's PUT the owner's object changed to match it",
		Answers: map[string]answer{"alice": {Status: 200, Length: 11}, "bob": {Status: 200, Length: 11}}}
	curl := func(n string) string {
		return `curl -sS -i -X PUT 'https://s.test/api/items/3' -H "Authorization: Bearer $` + n + `_TOKEN" -H 'Content-Type: application/json' --data-raw '{"name":"x"}'`
	}
	er := evRow(t, row, ans("alice", "answer", u, 200, `{"ok":true}`, curl("ALICE")), ans("bob", "answer", u, 200, `{"ok":true}`, curl("BOB")))
	d, err := buildReport(er, []string{"alice", "bob"}, time.Time{}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	md := d.markdown()
	for _, want := range []string{
		"(write): bob writes alice's item via PUT /api/items/{id}", "As bob, send the same write to alice's object.", "--data-raw '{\"name\":\"x\"}'",
		"> alice.har; after bob's PUT the owner's object changed to match it", "**high**", "before and after the write are not kept",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the report lacks %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "No control was asked") {
		t.Error("a write report asks for a control")
	}
}

func TestReportCreateSeverity(t *testing.T) {
	row := roleRow{Verdict: verdictWriteCreate}
	if lv := severityOf(row, classCreate, false).Level; lv != "low" {
		t.Errorf("a create by a signed-in role is %s, want low", lv)
	}
	if lv := severityOf(row, classCreate, true).Level; lv != "medium" {
		t.Errorf("a create with no credential is %s, want medium", lv)
	}
	if !carriesNoCredential(`curl -sS -i -X POST 'https://s.test/a' -H 'Content-Type: application/json' --data-raw '{"p":"$5"}'`) ||
		carriesNoCredential(`curl -sS -i -X POST 'https://s.test/a' -H "Authorization: Bearer $BOB_TOKEN"`) {
		t.Error("carriesNoCredential misreads a curl line")
	}
}

// roles -replay-writes post lists a create another role was let to send;
// report writes it up, from the directory and by -url -method.
func TestReportWritesUpACreateInAnotherRolesCollection(t *testing.T) {
	books := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		if user == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/books/v1" {
			var in struct {
				Title string `json:"book_title"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			books[in.Title] = user
			w.WriteHeader(200)
			fmt.Fprintf(w, `{"status":"success","by":%q}`, user)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/books/v1/") {
			title := strings.TrimPrefix(r.URL.Path, "/books/v1/")
			if owner, ok := books[title]; ok {
				fmt.Fprintf(w, `{"book_title":%q,"owner":%q}`, title, owner)
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	browse := func(file, user string) string {
		return writeHAR(t, file,
			harEntry("2026-10-29T10:00:00.000Z", "POST", srv.URL+"/books/v1", `{"book_title":"t-`+user+`"}`, 200, "Authorization", "Bearer tok-"+user, "Content-Type", "application/json"))
	}
	alice, bob := browse("alice.har", "alice"), browse("bob.har", "bob")
	dir := t.TempDir()
	if _, errOut, err := captureBoth(t, func() error {
		return cmdRoles([]string{"-json", "-dir", dir, "-har", "alice=" + alice, "-har", "bob=" + bob, "-replay-writes", "post"})
	}); err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	out := filepath.Join(dir, "out")
	if err := cmdReport([]string{"-dir", dir, "-format", "json", "-o", out + "/"}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.json"))
	// Both owners' creates share one URL and method: roles.db keeps a row
	// for each owner, and each is written up. The books the creates made
	// are read by the other role too, so cross-read reports join them:
	// only the creates are counted here.
	var docs []reportDoc
	for _, f := range files {
		b, _ := os.ReadFile(f)
		var d reportDoc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		if d.Method == http.MethodPost {
			docs = append(docs, d)
		}
	}
	if len(docs) != 2 {
		t.Fatalf("want a report for each owner's create, got %v", files)
	}
	for _, d := range docs {
		// The answers say nothing of whose book it is: accepted, no vulnerability named.
		if d.Class != classAccepted || d.Verdict != verdictWriteAccepted || d.Severity.Level != "low" {
			t.Errorf("class %q verdict %q severity %q", d.Class, d.Verdict, d.Severity.Level)
		}
		if !strings.HasPrefix(d.Title, "Create accepted: ") || !strings.Contains(d.Title, "'s POST to /books/v1 was accepted") || strings.Contains(d.Title, "Missing authorization") {
			t.Errorf("title %q", d.Title)
		}
		kinds := map[string]bool{}
		for _, a := range d.Evidence {
			kinds[a.Kind] = true
			if a.Kind == "reader" && a.Status != 200 {
				t.Errorf("the reader's answer is %d", a.Status)
			}
		}
		if !kinds["owner"] || !kinds["reader"] {
			t.Errorf("evidence kinds %v", kinds)
		}
	}
	// Both rows by -url and -method: a report each, in the directory.
	if out, _, err := captureBoth(t, func() error {
		return cmdReport([]string{"-dir", dir, "-url", srv.URL + "/books/v1", "-method", "POST", "-o", filepath.Join(dir, "both") + "/"})
	}); err != nil || !strings.Contains(out, "2 reports") {
		t.Fatalf("both owners' creates by -url: %v\n%s", err, out)
	}
	// One row by -url, -method and -owner, the report on standard output.
	rep, _, err := captureBoth(t, func() error {
		return cmdReport([]string{"-dir", dir, "-url", srv.URL + "/books/v1", "-method", "POST", "-owner", "alice"})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Create accepted:", "was accepted", "## Where the create comes from", "-X POST", "Expected: 200", "nothing says the server ignores who may create"} {
		if !strings.Contains(rep, want) {
			t.Errorf("the report lacks %q:\n%s", want, rep)
		}
	}
}

// Two owners' creates in one collection are two rows: roles show prints
// both, or one with -owner, and says which owner when it prints several.
func TestRolesShowTwoOwnersOfOneRoute(t *testing.T) {
	dir := t.TempDir()
	ev, err := store.OpenEvidence(filepath.Join(dir, evidenceFile))
	if err != nil {
		t.Fatal(err)
	}
	const u = "https://shop.example.test/books"
	mk := func(owner, reader string) store.EvidenceRow {
		er := evRow(t, roleRow{URL: u, Method: "POST", Owner: owner, Readers: []string{reader}, Verdict: verdictWriteCreate, Answers: map[string]answer{}},
			ans(reader, "answer", u, 200, `{"by":"`+reader+`"}`, "curl -X POST '"+u+"'"))
		er.Owner = owner
		return er
	}
	if err := ev.Save([]string{"alice", "bob"}, []store.EvidenceRow{mk("alice", "bob"), mk("bob", "alice")}); err != nil {
		t.Fatal(err)
	}
	ev.Close()
	out, err := captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, u, "-method", "post"}) })
	if err != nil || !strings.Contains(out, "owner alice") || !strings.Contains(out, "owner bob") {
		t.Fatalf("both owners are shown: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return cmdRolesShow([]string{"-dir", dir, u, "-method", "post", "-owner", "bob"}) })
	if err != nil || strings.Contains(out, "owner alice") || !strings.Contains(out, "POST "+u) {
		t.Fatalf("one owner: %v\n%s", err, out)
	}
	if err := cmdRolesShow([]string{"-dir", dir, u, "-method", "post", "-owner", "carol"}); err == nil {
		t.Error("an owner with no row is an error")
	}
	if err := cmdRolesShow([]string{"-dir", dir, u, "-method", "post", "-body", "bob"}); err == nil || exitCode(err) != exitUsage {
		t.Errorf("-body over two owners is a usage error: %v", err)
	}
}
