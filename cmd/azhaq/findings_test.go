package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// apacheFixture is a second web service: it names Apache 2.4.49 in
// its Server header, and its /version — the advisory's confirmation
// path — answers 404 with nothing that names a product or a version,
// so a confirmation read settles nothing and the lead stays claimed.
func apacheFixture(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Server", "Apache/2.4.49")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"vampi-like","version":"2.4.49"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const findingsAdvFixture = `[
  {"id":"CVE-TEST-0001","summary":"old nginx issue",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0001"}]},
  {"id":"CVE-TEST-0002","summary":"conditional nginx issue","azhaq_precondition":"only when the example module is enabled",
   "azhaq_confirm_path":"/version",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0002"}]},
  {"id":"CVE-TEST-0003","summary":"old apache issue","azhaq_confirm_path":"/version",
   "affected":[{"package":{"name":"Apache","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.4.50"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0003"}]}
]`

// parseTiers reads the findings output by tier: the lines of type finding, of
// type identification and of type lead.
func parseTiers(t *testing.T, body []byte) (findings, idents, leads []map[string]any) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("findings line is not JSON: %q (%v)", line, err)
		}
		switch row["type"] {
		case "finding":
			findings = append(findings, row)
		case "identification":
			idents = append(idents, row)
		case "lead":
			leads = append(leads, row)
		default:
			t.Fatalf("unexpected line in findings output: %s", line)
		}
	}
	return findings, idents, leads
}

// parseFindingLines is the proven rows and the identifications together (the
// records a label of verify applies to), and the leads.
func parseFindingLines(t *testing.T, body []byte) (findings, leads []map[string]any) {
	t.Helper()
	f, i, l := parseTiers(t, body)
	return append(f, i...), l
}

// A Juice Shop + VAmPI style pair in one run: report -findings writes
// one record per qualifying stored row — proved first, version-only
// and conditional distinct — and every field of every record is
// traceable to a stored advisory or verify row.
func TestFindingsReportFromAStoredRun(t *testing.T) {
	egress.Reset()
	shop := newCountingServer(t, true) // nginx 1.18.0, /version states it
	api := apacheFixture(t)            // Apache 2.4.49, /version settles nothing
	dir := t.TempDir()
	db := filepath.Join(dir, "w.db")
	seeds := filepath.Join(dir, "seeds.txt")
	if err := os.WriteFile(seeds, []byte(shop.URL+"/\n"+api.URL+"/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-list", seeds, "-db", db, "-json", "-depth", "0",
			"-no-paths", "-no-tech", "-no-favicon",
			"-advisories", "-advisories-confirm", "-advisory-source", writeAdvFixture(t, findingsAdvFixture),
			"-verify"})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}

	// The stored rows the records must trace back to.
	st, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := st.Observations()
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	storedVerify := map[string]verify.Result{}
	for _, r := range verifyResultsOf(obs) {
		if r.AdvisoryID != "" {
			storedVerify[r.AdvisoryID] = r
		}
	}
	storedLeads := map[string]advisory.Lead{}
	for _, l := range advisoryLeadsExpanded(obs) {
		storedLeads[l.AdvisoryID] = l
	}
	// One verify row and one advisory row for each of the two services; the
	// advisory rows hold the three advisories.
	if len(advisoryLeadsOf(obs)) != 2 || len(storedVerify) != 2 || len(storedLeads) != 3 {
		t.Fatalf("stored rows: %d verify, %d advisory leads holding %d; want 2, 2 and 3", len(storedVerify), len(advisoryLeadsOf(obs)), len(storedLeads))
	}

	outFile := filepath.Join(dir, "findings.jsonl")
	_, errOut, err = captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl", "-o", outFile})
	})
	if err != nil {
		t.Fatalf("report -findings: %v\n%s", err, errOut)
	}
	body, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	proven, findings, leads := parseTiers(t, body)
	if len(proven) != 0 || len(findings) != 3 || len(leads) != 0 {
		t.Fatalf("%d findings, %d identifications, %d leads; want 0, 3 and 0 (a version in a header is an identification):\n%s", len(proven), len(findings), len(leads), body)
	}
	for _, f := range findings {
		if f["tier"] != "identification" || f["observed_at"] == "" || f["reproduce"] == "" || f["excerpt"] == "" || f["how"] == "" || f["method"] == "" || f["target"] == "" {
			t.Errorf("identification %v has no complete proof: %v", f["advisory_id"], f)
		}
	}
	// Version-read first (no read here proved anything); the labels distinct and in rank order.
	wantLabels := []string{"version-read", "version-only", "conditional"}
	wantIDs := []string{"CVE-TEST-0001", "CVE-TEST-0003", "CVE-TEST-0002"}
	for i, f := range findings {
		if f["label"] != wantLabels[i] || f["advisory_id"] != wantIDs[i] {
			t.Fatalf("finding %d is %v %v, want %s %s (version-read first, labels never merged)", i, f["advisory_id"], f["label"], wantIDs[i], wantLabels[i])
		}
		// The top advisory of a service has the verify row; the others of it
		// are read from the advisory lead, so the findings list every one.
		vr, hasVerify := storedVerify[f["advisory_id"].(string)]
		if hasVerify == (f["advisory_id"] == "CVE-TEST-0002") {
			t.Fatalf("finding %v: stored verify row %v", f["advisory_id"], hasVerify)
		}
		lead := storedLeads[f["advisory_id"].(string)]
		// Every field traceable to the stored rows.
		if f["version"] != lead.VersionSeen || (hasVerify && f["version"] != vr.Version) {
			t.Errorf("finding %v version %v, stored verify %q lead %q", f["advisory_id"], f["version"], vr.Version, lead.VersionSeen)
		}
		if hasVerify && (f["evidence"] != vr.Evidence || f["command"] != vr.Command) {
			t.Errorf("finding %v evidence/command not the stored verify row's: %v", f["advisory_id"], f)
		}
		if f["evidence"] == "" {
			t.Errorf("finding %v has no evidence", f["advisory_id"])
		}
		if f["host"] != "127.0.0.1" || int(f["port"].(float64)) != lead.Port {
			t.Errorf("finding %v host/port %v:%v, stored lead port %d", f["advisory_id"], f["host"], f["port"], lead.Port)
		}
		if f["product"] != lead.Product || f["advisory_url"] != lead.URL {
			t.Errorf("finding %v product/advisory_url %v %v, stored lead %q %q", f["advisory_id"], f["product"], f["advisory_url"], lead.Product, lead.URL)
		}
		if hasVerify && f["command"] != "azhaq run -verify" || !hasVerify && !strings.HasPrefix(f["command"].(string), "azhaq run ") {
			t.Errorf("finding %v command %q, want the command that produced it", f["advisory_id"], f["command"])
		}
	}

	// The export formats carry the same records.
	var buf bytes.Buffer
	if err := exportAs(db, "findings", "", &buf); err != nil {
		t.Fatal(err)
	}
	ef, el := parseFindingLines(t, buf.Bytes())
	if len(ef) != len(findings) || len(el) != 0 {
		t.Fatalf("export findings: %d findings %d leads, want %d and 0", len(ef), len(el), len(findings))
	}
	buf.Reset()
	if err := exportAs(db, "findings-md", "", &buf); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	for _, want := range []string{"# Findings", "## Identifications (3)", "### Version-read (1)", "### Version-only (1)", "### Conditional (1)", "CVE-TEST-0001", "CVE-TEST-0003", "CVE-TEST-0002"} {
		if !strings.Contains(md, want) {
			t.Errorf("findings markdown lacks %q:\n%s", want, md)
		}
	}
}

// A run with no qualifying rows writes an explicit empty record set
// and exits 0, in both renderings and in the export.
func TestFindingsEmptyRecordSet(t *testing.T) {
	egress.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", db, "-depth", "0", "-no-paths", "-no-tech", "-no-favicon"})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	out, errOut, err := captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-format", "jsonl"})
	})
	if err != nil {
		t.Fatalf("report -findings on an empty run: %v\n%s (want exit 0)", err, errOut)
	}
	if strings.TrimSpace(out) != `{"type":"findings","findings":0,"identifications":0,"leads":0}` {
		t.Errorf("empty JSONL record set is %q, want the explicit empty line", strings.TrimSpace(out))
	}
	out, _, err = captureBoth(t, func() error {
		return cmdReport([]string{"-findings", "-db", db, "-format", "md"})
	})
	if err != nil {
		t.Fatalf("report -findings md on an empty run: %v", err)
	}
	if !strings.Contains(out, "No qualifying rows") {
		t.Errorf("empty Markdown record set does not say so:\n%s", out)
	}
	var buf bytes.Buffer
	if err := exportAs(db, "findings", "", &buf); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != `{"type":"findings","findings":0,"identifications":0,"leads":0}` {
		t.Errorf("empty export is %q, want the explicit empty line", strings.TrimSpace(buf.String()))
	}
}

// The builder: labels come from the stored rows, a verify row covers
// its advisory lead (no second record), a not-affected lead is no
// record, and an unproved map hint is a lead, listed separately.
func TestBuildFindings(t *testing.T) {
	verifyObs := func(r verify.Result) types.StoredObservation {
		raw, _ := json.Marshal(r)
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-verify", Kind: "verify", Payload: raw}}
	}
	leadObs := func(l advisory.Lead) types.StoredObservation {
		raw, _ := json.Marshal(l)
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-advisories", Kind: "advisory", Payload: raw}}
	}
	g := &graphView{
		args: []string{"-url", "http://app.test/", "-verify"},
		obs: []types.StoredObservation{
			verifyObs(verify.Result{Kind: verify.KindUnauthenticatedRead, Label: verify.Proved, Severity: "high",
				Host: "127.0.0.1", Port: 6379, Target: "127.0.0.1:6379", Product: "Redis", Version: "7.2.0",
				Request: "INFO server", Evidence: "# Server redis_version:7.2.0", Command: "azhaq run -verify",
				Proof: &proof.Proof{ObservedAt: "2026-11-12T10:00:00Z", Method: "INFO server", Target: "127.0.0.1:6379", RequestBytes: "INFO server\\r\\n",
					Excerpt: "$900\\r\\n# Server\\r\\nredis_version:7.2.0", ExcerptPart: "response", How: "azhaq-verify",
					Reproduce: "printf '%b' 'INFO server\\r\\n' | nc -w 3 127.0.0.1 6379"}}),
			verifyObs(verify.Result{Kind: verify.KindAdvisoryPrecond, Label: verify.Proved, Severity: "medium",
				Host: "app.test", Port: 80, Target: "app.test", Product: "nginx", Version: "1.18.0",
				AdvisoryID: "CVE-1", AdvisoryURL: "https://example.test/CVE-1",
				Request: "GET /version", Evidence: "GET /version answered 200", Command: "azhaq run -verify"}),
			// The same lead as stored by -advisories: covered by the
			// verify row above, so no second record.
			leadObs(advisory.Lead{AdvisoryID: "CVE-1", URL: "https://example.test/CVE-1", Target: "app.test",
				Host: "app.test", Port: 80, Product: "nginx", VersionSeen: "1.18.0", Label: advisory.LabelAffected,
				Confidence: advisory.Observed, ConfirmReq: "GET /version", Read: "GET /version answered 200"}),
			leadObs(advisory.Lead{AdvisoryID: "CVE-2", URL: "https://example.test/CVE-2", Target: "app.test",
				Host: "app.test", Port: 80, Product: "nginx", VersionSeen: "1.18.0", Label: advisory.LabelConditional,
				Precondition: "only when the example module is enabled"}),
			leadObs(advisory.Lead{AdvisoryID: "CVE-3", URL: "https://example.test/CVE-3", Target: "app.test",
				Host: "app.test", Port: 80, Product: "nginx", VersionSeen: "9.9.9", Label: advisory.LabelNotAffected}),
		},
		rows: []engine.MapEntry{
			{Entity: types.Entity{Type: types.TypeURL, Key: "http://app.test/api/things"}, Coverage: "hint", Proof: "GET answers 404; called with POST"},
			{Entity: types.Entity{Type: types.TypeURL, Key: "http://app.test/"}, Coverage: "visited", Proof: "answered 200"},
		},
	}
	set := buildFindings(g)
	findings, leads := set.Findings, set.Leads
	if len(findings) != 1 || findings[0].Product != "Redis" || findings[0].Tier != "finding" {
		t.Fatalf("%d findings, want 1 (the redis read, with its proof): %+v", len(findings), findings)
	}
	idents := set.Identifications
	if len(idents) != 2 || idents[0].Label != verify.VersionRead || idents[1].Label != verify.Conditional {
		t.Fatalf("%d identifications, want 2 (CVE-1 version-read once, CVE-2 conditional): %+v", len(idents), idents)
	}
	findings = append(findings, idents...)
	byID := map[string]findingRecord{}
	for _, f := range findings {
		byID[f.AdvisoryID] = f
		if f.AdvisoryID == "CVE-3" {
			t.Errorf("a not-affected lead became a finding: %+v", f)
		}
	}
	// The row was stored by an azhaq that called a stated version "proved" at
	// medium: it reads as what it settled.
	if byID["CVE-1"].Label != verify.VersionRead || byID["CVE-1"].Severity != "info" {
		t.Errorf("CVE-1 record %+v, want version-read at info", byID["CVE-1"])
	}
	if byID["CVE-1"].Collector != "azhaq-verify" || byID["CVE-1"].Command != "azhaq run -verify" {
		t.Errorf("CVE-1 record %+v, want the stored verify row's collector and command", byID["CVE-1"])
	}
	if byID["CVE-2"].Collector != "azhaq-advisories" || byID["CVE-2"].Precondition == "" {
		t.Errorf("CVE-2 record %+v, want an advisories record naming the precondition", byID["CVE-2"])
	}
	if len(leads) != 1 || leads[0].Kind != "hint" || leads[0].Label != "lead" || leads[0].URL != "http://app.test/api/things" {
		t.Fatalf("leads %+v, want the one unproved hint", leads)
	}
	if !strings.Contains(leads[0].Evidence, "called with POST") {
		t.Errorf("lead evidence %q, want the map row's proof", leads[0].Evidence)
	}
	// Nothing here may be labelled proved that its row does not prove.
	for _, f := range findings {
		if f.Label == verify.Proved && f.Evidence == "" {
			t.Errorf("a proved record with no evidence: %+v", f)
		}
	}
}

// A handshake result keeps its own kind in the record and in Markdown, and
// ranks below a data-store read.
func TestFindingsKeepAHandshakeKind(t *testing.T) {
	raw, _ := json.Marshal(verify.Result{Kind: verify.KindUnauthenticatedHandshake, Label: verify.Proved, Severity: "info",
		Host: "10.0.0.5", Port: 5005, Target: "10.0.0.5:5005", Request: "JDWP-Handshake", Evidence: "JDWP-Handshake", Command: "azhaq ports -verify"})
	g := &graphView{obs: []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-verify", Kind: "verify", Payload: raw}}}}
	set := buildFindings(g)
	findings := set.Identifications
	if len(findings) != 1 || len(set.Findings) != 0 || findings[0].Kind != "unauthenticated-handshake" || findings[0].Severity != "info" {
		t.Fatalf("%+v, want one unauthenticated-handshake record, info, an identification", set)
	}
	if md := findingMarkdown(findings[0]); !strings.Contains(md, "**info** unauthenticated-handshake on 10.0.0.5:5005") {
		t.Errorf("markdown %q", md)
	}
}
