package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// useBuiltinIndex gives the test the index embedded in the binary, which
// the other tests of this package have emptied (see TestMain).
func useBuiltinIndex(t *testing.T) {
	t.Helper()
	t.Cleanup(advisory.SetBuiltin(nil))
}

// apacheServer announces Apache httpd of the given version in its Server
// header, as a real one does, and answers any path.
func apacheServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/"+version+" (Unix)")
		fmt.Fprint(w, "<html><head><title>It works</title></head><body>hello</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ftpServer is a stand-in service that says ProFTPD 1.3.5 first, as a
// real one does, and closes.
func ftpServer(t *testing.T, version string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				fmt.Fprintf(c, "220 ProFTPD %s Server (Debian) [::ffff:127.0.0.1]\r\n", version)
				bufio.NewReader(c).ReadString('\n')
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// advRow is an advisory line of the output: the lead of one service.
type advRow struct {
	ID, Label, URL, Range, Source, Product, Version, Target string
	KEV                                                     bool
	CVSS                                                    float64
	Counts                                                  map[string]int
	KEVCount                                                int
	MaxCVSS                                                 float64
	Refs                                                    []advRef
}

type advRef struct {
	ID    string  `json:"id"`
	URL   string  `json:"url"`
	Label string  `json:"label"`
	Range string  `json:"range"`
	KEV   bool    `json:"kev"`
	CVSS  float64 `json:"cvss"`
	Index bool    `json:"index"`
}

func advRows(out string) []advRow {
	var rows []advRow
	for _, line := range strings.Split(out, "\n") {
		var r struct {
			Type string `json:"type"`
			advisory.Lead
		}
		if json.Unmarshal([]byte(line), &r) != nil || r.Type != "advisory" {
			continue
		}
		row := advRow{ID: r.AdvisoryID, Label: r.Label, URL: r.URL, Range: r.AffectedRange, Source: r.Source, Product: r.Product,
			Version: r.VersionSeen, Target: r.Target, KEV: r.KEV, CVSS: r.CVSS, Counts: r.Counts, KEVCount: r.KEVCount, MaxCVSS: r.MaxCVSS}
		for _, a := range r.Advisories {
			row.Refs = append(row.Refs, advRef{a.ID, a.URL, a.Label, a.Range, a.KEV, a.CVSS, a.Index})
		}
		rows = append(rows, row)
	}
	return rows
}

// ref finds an advisory among the lists of the service leads.
func ref(rows []advRow, id string) *advRef {
	for i := range rows {
		for j := range rows[i].Refs {
			if rows[i].Refs[j].ID == id {
				return &rows[i].Refs[j]
			}
		}
	}
	return nil
}

func runDefault(t *testing.T, args ...string) (string, report) {
	t.Helper()
	egress.Reset()
	db := filepath.Join(t.TempDir(), "w.db")
	args = append([]string{"-db", db, "-json", "-depth", "0", "-no-paths", "-no-tech", "-no-favicon"}, args...)
	out, errOut, err := captureBoth(t, func() error { return cmdRun(args) })
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	return out, lastReport(t, errOut)
}

func noteOf(rep report) string {
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "advisories: ") {
			return n
		}
	}
	return ""
}

// `run` with no advisory flag matches the product and version a server
// announces against the index azhaq carries, and says it in one line for
// the service: the top advisory, the count by label, the KEV count and the
// highest score, with every advisory in the lead's list.
func TestRunNamesTheAdvisoriesOfAConfirmedVersionByDefault(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.49")
	out, rep := runDefault(t, "-url", srv.URL+"/")
	rows := advRows(out)
	// Exactly one advisory line for the one service, however many advisories it has.
	if len(rows) != 1 {
		t.Fatalf("%d advisory lines for one service, want 1:\n%s", len(rows), out)
	}
	l := rows[0]
	if l.ID != "CVE-2021-41773" || l.Label != "affected" || l.URL != "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" || !l.KEV || l.CVSS != 9.8 ||
		l.Version != "2.4.49" || !strings.Contains(l.Range, "2.4.49") || !strings.HasPrefix(l.Source, "azhaq advisory index ") {
		t.Errorf("top advisory of the lead %+v", l)
	}
	if len(l.Refs) < 50 || l.Counts["affected"] < 50 || l.KEVCount < 3 || l.MaxCVSS != 9.8 {
		t.Errorf("lead counts %v kev %d max %.1f over %d advisories", l.Counts, l.KEVCount, l.MaxCVSS, len(l.Refs))
	}
	if r := ref(rows, "CVE-2021-42013"); r == nil || r.Label != "affected" || !r.KEV {
		t.Errorf("CVE-2021-42013 %+v", r)
	}
	// The list is complete and ordered: the advisories that apply first, the
	// exploited ones before the rest, higher scores first.
	total := 0
	for _, n := range l.Counts {
		total += n
	}
	if total != len(l.Refs) {
		t.Errorf("counts add up to %d, the list holds %d", total, len(l.Refs))
	}
	for i := 1; i < len(l.Refs); i++ {
		p, c := l.Refs[i-1], l.Refs[i]
		pa, ca := p.Label != "not affected", c.Label != "not affected"
		if pa != ca && ca || pa == ca && p.KEV != c.KEV && c.KEV || pa == ca && p.KEV == c.KEV && p.CVSS < c.CVSS {
			t.Fatalf("the list is out of order at %d: %+v then %+v", i, p, c)
		}
	}
	if len(rep.Advisories) != 1 || len(rep.Advisories[0].Advisories) != len(l.Refs) {
		t.Errorf("summary holds %d leads, the first with %d advisories, output %d", len(rep.Advisories), len(rep.Advisories[0].Advisories), len(l.Refs))
	}
	m, _ := advisory.BuiltinMeta()
	note := noteOf(rep)
	if !strings.Contains(note, "1 leads, one for each of 1 confirmed product versions, holding ") || !strings.Contains(note, " affected, ") || !strings.Contains(note, m.Label()) {
		t.Errorf("the summary's note does not count the advisories by label and name the index: %q", note)
	}
	// The run's text output is one line too.
	egress.Reset()
	text, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", filepath.Join(t.TempDir(), "w.db"), "-depth", "0", "-no-paths", "-no-tech", "-no-favicon"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(text, "advisory: Apache 2.4.49"); n != 1 {
		t.Errorf("%d advisory lines in the text output, want 1:\n%s", n, text)
	}
}

// Each service has its own line: two servers, two lines.
func TestOneAdvisoryLinePerService(t *testing.T) {
	useBuiltinIndex(t)
	a, b := apacheServer(t, "2.4.49"), apacheServer(t, "2.4.51")
	list := filepath.Join(t.TempDir(), "seeds.txt")
	if err := os.WriteFile(list, []byte(a.URL+"/\n"+b.URL+"/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, rep := runDefault(t, "-list", list)
	rows := advRows(out)
	if len(rows) != 2 || len(rep.Advisories) != 2 {
		t.Fatalf("%d advisory lines and %d leads for two services, want 2 and 2:\n%s", len(rows), len(rep.Advisories), out)
	}
	if rows[0].Target == rows[1].Target {
		t.Errorf("two lines for one target")
	}
}

// A version just outside the range is labelled so, and the counts in the
// summary follow the labels.
func TestRunLabelsAVersionOutsideTheRange(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.51")
	out, rep := runDefault(t, "-url", srv.URL+"/")
	rows := advRows(out)
	r := ref(rows, "CVE-2021-41773")
	if r == nil || r.Label != "not affected" || !r.KEV {
		t.Fatalf("advisory %+v, want CVE-2021-41773 not affected (a KEV advisory is listed even when it does not apply)", r)
	}
	na := rows[0].Counts["not affected"]
	if na < 2 {
		t.Errorf("counts %v", rows[0].Counts)
	}
	if !strings.Contains(noteOf(rep), fmt.Sprintf(", %d not affected, ", na)) {
		t.Errorf("note %q does not count %d not affected", noteOf(rep), na)
	}
}

// `ports` matches the product and version a port announced, with no flag.
func TestPortsNamesTheAdvisoriesOfAConfirmedVersionByDefault(t *testing.T) {
	useBuiltinIndex(t)
	egress.Reset()
	port := ftpServer(t, "1.3.5")
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", strconv.Itoa(port), "-db", db, "-json"})
	})
	if err != nil {
		t.Fatalf("ports: %v\n%s", err, errOut)
	}
	rows := advRows(out)
	r := ref(rows, "CVE-2015-3306")
	if len(rows) != 1 || r == nil || r.Label != "affected" || rows[0].Product != "ProFTPD" || rows[0].Version != "1.3.5" {
		t.Fatalf("%d lead lines, advisory %+v in\n%s", len(rows), r, out)
	}
	rep := lastReport(t, errOut)
	if rep.Results != 1 || rep.Counts["advisory leads"] != 1 || len(rep.Advisories) != 1 {
		t.Errorf("results %d counts %v advisories %d, lead lines %d", rep.Results, rep.Counts, len(rep.Advisories), len(rows))
	}
}

// -advisories=false turns the matching off, in run and in ports.
func TestAdvisoriesFalseTurnsTheMatchingOff(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.49")
	out, rep := runDefault(t, "-url", srv.URL+"/", "-advisories=false")
	if rows := advRows(out); len(rows) != 0 || len(rep.Advisories) != 0 {
		t.Errorf("run matched with -advisories=false: %d lines, %d in the summary", len(rows), len(rep.Advisories))
	}
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "advisories: ") {
			t.Errorf("note %q with the matching off", n)
		}
	}
	egress.Reset()
	port := ftpServer(t, "1.3.5")
	pout, perr, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", strconv.Itoa(port), "-db", filepath.Join(t.TempDir(), "w.db"), "-json", "-advisories=false"})
	})
	if err != nil {
		t.Fatalf("ports: %v\n%s", err, perr)
	}
	if rows := advRows(pout); len(rows) != 0 {
		t.Errorf("ports matched with -advisories=false: %d lines", len(rows))
	}
}

// -advisory-source adds the user's records to the index; it does not replace it.
func TestAdvisorySourceAddsToTheIndex(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.49")
	fixture := `[{"id":"CVE-TEST-0100","summary":"a record of mine",
	  "affected":[{"package":{"name":"Apache httpd"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.4.0"},{"fixed":"2.4.50"}]}]}],
	  "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0100"}]}]`
	out, _ := runDefault(t, "-url", srv.URL+"/", "-advisory-source", writeAdvFixture(t, fixture))
	rows := advRows(out)
	mine, idx := ref(rows, "CVE-TEST-0100"), ref(rows, "CVE-2021-41773")
	if len(rows) != 1 || mine == nil || mine.Label != "affected" || mine.Index || mine.URL != "https://example.test/CVE-TEST-0100" {
		t.Errorf("%d lines; the user's advisory %+v", len(rows), mine)
	}
	if idx == nil || !idx.Index {
		t.Errorf("the index's advisory %+v is gone beside the user's records", idx)
	}
}

// The usage rules of the flags: a source or a confirmation with the matching off.
func TestAdvisoryFlagsUsage(t *testing.T) {
	_, _, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", "http://127.0.0.1:1/", "-advisories=false", "-advisory-source", "x.json"})
	})
	if err == nil || !strings.Contains(err.Error(), "-advisories=false") {
		t.Errorf("-advisory-source with -advisories=false: %v", err)
	}
	_, _, err = captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", "1", "-advisories=false", "-advisories-confirm"})
	})
	if err == nil {
		t.Error("-advisories-confirm with -advisories=false was accepted")
	}
}

// The plan and `azhaq version` name the index and its date.
func TestPlanAndVersionNameTheIndex(t *testing.T) {
	useBuiltinIndex(t)
	m, err := advisory.BuiltinMeta()
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("advisory index %s (%d records)", m.Built, m.Records)
	if m.Label() != want {
		t.Fatalf("label %q", m.Label())
	}
	text, _, _ := cli(t, "plan", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1", "-sources", "none")
	if !strings.Contains(text, "advisories: "+want) {
		t.Errorf("the plan does not say %q:\n%s", want, text)
	}
	js, _, _ := cli(t, "plan", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1", "-sources", "none", "-json")
	var plan runPlan
	for _, line := range strings.Split(js, "\n") {
		if json.Unmarshal([]byte(line), &plan) == nil && plan.Advisories != "" {
			break
		}
	}
	if !strings.HasPrefix(plan.Advisories, want) {
		t.Errorf("the plan's advisories %q", plan.Advisories)
	}
	off, _, _ := cli(t, "plan", "-url", "http://127.0.0.1:1/", "-allow", "127.0.0.1", "-sources", "none", "-advisories=false")
	if !strings.Contains(off, "advisories: off") {
		t.Errorf("a plan with the matching off:\n%s", off)
	}
	ver, _, _ := cli(t, "version")
	if !strings.Contains(ver, want) {
		t.Errorf("azhaq version does not say %q:\n%s", want, ver)
	}
}

// apacheCounting is a stand-in that announces Apache httpd 2.4.49 and
// records what it is asked.
func apacheCounting(t *testing.T) (*countingServer, []types.StoredObservation) {
	t.Helper()
	cs := &countingServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.hits = append(cs.hits, r.Method+" "+r.URL.Path)
		cs.mu.Unlock()
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		fmt.Fprint(w, "hello")
	}))
	t.Cleanup(cs.Close)
	raw, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "ip": "127.0.0.1",
		"services": []map[string]any{{"port": cs.port(), "service": "http", "product": "Apache httpd", "version": "2.4.49"}},
	})
	return cs, []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}}}
}

// -advisories-confirm reads once for each path, not once for each advisory:
// ninety advisories that name no path are one GET of /, and each is judged
// against its answer. The read is a ledger line and counts against the budget.
func TestAdvisoriesConfirmReadsOncePerPath(t *testing.T) {
	useBuiltinIndex(t)
	egress.Reset()
	cs, obs := apacheCounting(t)
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ledPath := filepath.Join(dir, "ledger.jsonl")
	led, err := ledger.Open(ledPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(led)
	defer ledger.Use(nil)
	// Two records of the user's name /version, one names /: three paths' worth
	// of advisories beside the index's, which name none.
	fixture := `[{"id":"CVE-TEST-0201","azhaq_confirm_path":"/version","affected":[{"package":{"name":"Apache httpd"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.4.0"},{"fixed":"2.4.50"}]}]}]},
	  {"id":"CVE-TEST-0202","azhaq_confirm_path":"/version","affected":[{"package":{"name":"Apache httpd"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.4.0"},{"fixed":"2.4.50"}]}]}]},
	  {"id":"CVE-TEST-0203","affected":[{"package":{"name":"Apache httpd"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.4.0"},{"fixed":"2.4.50"}]}]}]}]`
	leads, failures, note := advisoryStage(context.Background(), st, obs,
		advisoryFlags{on: true, confirm: true, builtin: true, source: writeAdvFixture(t, fixture)})
	if len(failures) > 0 {
		t.Fatalf("failures %v", failures)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	got := cs.requests()
	slices.Sort(got)
	if !slices.Equal(got, []string{"GET /", "GET /version"}) {
		t.Fatalf("the target saw %v, want one GET of / and one of /version for all the advisories", got)
	}
	n := 0
	if err := ledger.Read(ledPath, func(e ledger.Entry) error {
		if e.Kind == "http" && e.Collector == "azhaq-advisories" {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("the ledger holds %d reads, want 2", n)
	}
	if len(leads) != 1 || len(leads[0].Advisories) < 50 {
		t.Fatalf("leads %d", len(leads))
	}
	// Every advisory that applies was judged against an answer.
	for _, r := range leads[0].Advisories {
		// Judged against the answer: observed where nothing else is open, inferred
		// where the record also names a platform the read does not show.
		if want := map[string]string{"affected": "observed", "conditional": "inferred", "not affected": "claimed"}[r.Label]; r.Confidence != want {
			t.Errorf("advisory %s is %s, confidence %q, want %q", r.ID, r.Label, r.Confidence, want)
		}
	}
	if !strings.Contains(note, "confirmation: 2 reads for ") {
		t.Errorf("note %q does not say 2 reads", note)
	}
}

// -verify makes one version-evidence row for a service, however many
// advisories it has, and the findings records still list them all.
func TestVerifyGivesOneRowPerService(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.49")
	db := filepath.Join(t.TempDir(), "w.db")
	egress.Reset()
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", srv.URL + "/", "-db", db, "-json", "-depth", "0", "-no-paths", "-no-tech", "-no-favicon", "-verify"})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	rep := lastReport(t, errOut)
	var rows []verify.Result
	for _, r := range rep.Verify {
		if r.Kind == verify.KindAdvisoryPrecond {
			rows = append(rows, r)
		}
	}
	if len(rows) != 1 || rows[0].AdvisoryID != "CVE-2021-41773" || rows[0].Label != verify.VersionOnly || !strings.Contains(rows[0].Evidence, " advisories in all match this version") {
		t.Fatalf("verify rows %+v, want one for the service, its top advisory, version-only", rep.Verify)
	}
	// The findings keep every advisory: JSON Lines one record each, Markdown one bullet.
	var buf bytes.Buffer
	if err := exportAs(db, "findings", "", &buf); err != nil {
		t.Fatal(err)
	}
	found, _ := parseFindingLines(t, buf.Bytes())
	if len(found) != len(rep.Advisories[0].Advisories)-rep.Advisories[0].Counts["not affected"] {
		t.Errorf("%d findings, the lead holds %d advisories that apply", len(found), len(rep.Advisories[0].Advisories)-rep.Advisories[0].Counts["not affected"])
	}
	if found[0]["advisory_id"] != "CVE-2021-41773" || found[0]["kev"] != true {
		t.Errorf("first finding %v, want the exploited top advisory", found[0])
	}
	buf.Reset()
	if err := exportAs(db, "findings-md", "", &buf); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	labels := map[any]bool{}
	for _, f := range found {
		labels[f["label"]] = true
	}
	bullets := strings.Split(md, "\n- ")[1:]
	if len(bullets) != len(labels) || !strings.Contains(md, "CVE-2021-41773, CVE-2021-42013") || !strings.Contains(md, " more (") {
		t.Errorf("the Markdown findings are %d bullets, want one for each of the %d labels, the first with the first ten ids and \"and N more\":\n%s", len(bullets), len(labels), md)
	}
	for _, b := range bullets {
		head, _, _ := strings.Cut(b, "; evidence:")
		if n := strings.Count(head, "CVE-"); n > 10 {
			t.Errorf("a bullet lists %d ids, want at most 10 and \"and N more\": %s", n, head)
		}
	}
}
