package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/egress"
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

type advRow struct {
	ID, Label, URL, Range, Source, Product, Version string
	KEV                                             bool
	CVSS                                            float64
}

func advRows(out string) []advRow {
	var rows []advRow
	for _, line := range strings.Split(out, "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil || r["type"] != "advisory" {
			continue
		}
		str := func(k string) string { s, _ := r[k].(string); return s }
		kev, _ := r["kev"].(bool)
		cvss, _ := r["cvss"].(float64)
		rows = append(rows, advRow{ID: str("advisory_id"), Label: str("label"), URL: str("url"), Range: str("affected_range"),
			Source: str("source"), Product: str("product"), Version: str("version_seen"), KEV: kev, CVSS: cvss})
	}
	return rows
}

func find(rows []advRow, id string) *advRow {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
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

// `run` with no advisory flag matches the product and version a server
// announces against the index azhaq carries: the lead has the advisory id,
// its URL, its label and the range that says why.
func TestRunNamesTheAdvisoriesOfAConfirmedVersionByDefault(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.49")
	out, rep := runDefault(t, "-url", srv.URL+"/")
	rows := advRows(out)
	l := find(rows, "CVE-2021-41773")
	if l == nil {
		t.Fatalf("no lead for CVE-2021-41773:\n%s", out)
	}
	if l.Label != "affected" || l.URL != "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" || !l.KEV || l.CVSS != 9.8 ||
		l.Version != "2.4.49" || !strings.Contains(l.Range, "2.4.49") || !strings.HasPrefix(l.Source, "azhaq advisory index ") {
		t.Errorf("lead %+v", l)
	}
	if find(rows, "CVE-2021-42013") == nil {
		t.Error("no lead for CVE-2021-42013")
	}
	if len(rep.Advisories) != len(rows) || len(rows) < 2 {
		t.Errorf("summary holds %d leads, output %d", len(rep.Advisories), len(rows))
	}
	m, _ := advisory.BuiltinMeta()
	var note string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "advisories: ") {
			note = n
		}
	}
	if !strings.Contains(note, fmt.Sprintf("%d leads (", len(rows))) || !strings.Contains(note, " affected, ") || !strings.Contains(note, m.Label()) {
		t.Errorf("the summary's note does not count the leads by label and name the index: %q", note)
	}
}

// A version just outside the range is labelled so, and the counts in the
// summary follow the labels.
func TestRunLabelsAVersionOutsideTheRange(t *testing.T) {
	useBuiltinIndex(t)
	srv := apacheServer(t, "2.4.51")
	out, rep := runDefault(t, "-url", srv.URL+"/")
	rows := advRows(out)
	l := find(rows, "CVE-2021-41773")
	if l == nil || l.Label != "not affected" || !l.KEV {
		t.Fatalf("lead %+v, want CVE-2021-41773 not affected (a KEV advisory is listed even when it does not apply)", l)
	}
	var na int
	for _, r := range rows {
		if r.Label == "not affected" {
			na++
		}
	}
	var note string
	for _, n := range rep.Notes {
		if strings.HasPrefix(n, "advisories: ") {
			note = n
		}
	}
	if !strings.Contains(note, fmt.Sprintf(", %d not affected, ", na)) {
		t.Errorf("note %q does not count %d not affected", note, na)
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
	l := find(rows, "CVE-2015-3306")
	if l == nil || l.Label != "affected" || l.Product != "ProFTPD" || l.Version != "1.3.5" {
		t.Fatalf("lead %+v in\n%s", l, out)
	}
	rep := lastReport(t, errOut)
	if rep.Results != 1 || rep.Counts["advisory leads"] != len(rows) || len(rep.Advisories) != len(rows) {
		t.Errorf("results %d counts %v advisories %d, leads %d", rep.Results, rep.Counts, len(rep.Advisories), len(rows))
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
	mine, idx := find(rows, "CVE-TEST-0100"), find(rows, "CVE-2021-41773")
	if mine == nil || mine.Label != "affected" || mine.Source != "" || mine.URL != "https://example.test/CVE-TEST-0100" {
		t.Errorf("the user's lead %+v", mine)
	}
	if idx == nil || idx.Source == "" {
		t.Errorf("the index's lead %+v is gone beside the user's records", idx)
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
