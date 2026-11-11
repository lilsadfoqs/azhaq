package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

const advFixture = `[
  {"id":"CVE-TEST-0001","summary":"old nginx issue",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0001"}]},
  {"id":"CVE-TEST-0002","summary":"conditional nginx issue","azhaq_precondition":"only when the example module is enabled",
   "azhaq_confirm_path":"/version",
   "affected":[{"package":{"name":"nginx","ecosystem":"test"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
   "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0002"}]}
]`

func writeAdvFixture(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advisories.json")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// countingServer is a stand-in service: every answer names nginx
// 1.18.0, and /version states it as JSON. It records what it was sent.
type countingServer struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string
}

func newCountingServer(t *testing.T, versionSignal bool) *countingServer {
	t.Helper()
	cs := &countingServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.hits = append(cs.hits, r.Method+" "+r.URL.Path)
		cs.mu.Unlock()
		if versionSignal {
			w.Header().Set("Server", "nginx/1.18.0")
		}
		if r.URL.Path == "/version" && versionSignal {
			fmt.Fprint(w, `{"product":"nginx","version":"1.18.0"}`)
			return
		}
		fmt.Fprint(w, "hello")
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *countingServer) requests() []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]string(nil), cs.hits...)
}

func (cs *countingServer) port() int {
	return cs.Listener.Addr().(*net.TCPAddr).Port
}

// portsObs is what a port scan of cs would have stored: nginx 1.18.0
// confirmed on its port, from its own answer.
func portsObs(cs *countingServer) []types.StoredObservation {
	raw, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "ip": "127.0.0.1",
		"services": []map[string]any{{"port": cs.port(), "service": "http", "product": "nginx", "version": "1.18.0"}},
	})
	return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}}}
}

// Part 1 sends nothing: the match is a lookup over what the run already
// holds, so the target sees zero requests while the match is decided.
func TestAdvisoryStagePart1SendsNothing(t *testing.T) {
	egress.Reset()
	cs := newCountingServer(t, true)
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	leads, failures, note := advisoryStage(context.Background(), st, portsObs(cs),
		advisoryFlags{on: true, source: writeAdvFixture(t, advFixture)})
	if len(failures) > 0 {
		t.Fatalf("failures %v", failures)
	}
	if got := cs.requests(); len(got) != 0 {
		t.Fatalf("Part 1 sent %v to the target, want nothing", got)
	}
	if len(leads) != 2 {
		t.Fatalf("leads %+v, want 2", leads)
	}
	byID := map[string]struct {
		label, url, rng string
	}{}
	for _, l := range leads {
		byID[l.AdvisoryID] = struct{ label, url, rng string }{l.Label, l.URL, l.AffectedRange}
		if l.VersionSeen != "1.18.0" || l.Confidence != "" {
			t.Errorf("lead %+v: version seen and no confidence without confirmation", l)
		}
	}
	if byID["CVE-TEST-0001"].label != "affected" || byID["CVE-TEST-0001"].url != "https://example.test/CVE-TEST-0001" {
		t.Errorf("affected lead %+v", byID["CVE-TEST-0001"])
	}
	if byID["CVE-TEST-0002"].label != "conditional" {
		t.Errorf("conditional lead %+v", byID["CVE-TEST-0002"])
	}
	if !strings.Contains(note, "2 leads (1 affected, 0 not affected, 1 conditional)") {
		t.Errorf("note %q does not count the leads printed", note)
	}
	// The leads are stored rows, so the summary's counts derive from them.
	stored, _ := st.Observations()
	if got := advisoryLeadsOf(stored); len(got) != len(leads) {
		t.Errorf("stored leads %d, printed %d", len(got), len(leads))
	}
}

// Part 2 sends only the benign reads the advisories name, each counted
// in the ledger: a GET of /version and, for the advisory that names no
// path, a GET of /. A read that states the version settles what it can:
// observed where nothing else is open, inferred where a precondition
// the read does not show remains.
func TestAdvisoryStageConfirmReadsOnlyAndLedgers(t *testing.T) {
	egress.Reset()
	cs := newCountingServer(t, true)
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
	leads, failures, _ := advisoryStage(context.Background(), st, portsObs(cs),
		advisoryFlags{on: true, confirm: true, source: writeAdvFixture(t, advFixture)})
	if len(failures) > 0 {
		t.Fatalf("failures %v", failures)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	got := cs.requests()
	if len(got) != 2 {
		t.Fatalf("confirmation sent %v, want exactly the two benign reads", got)
	}
	for _, hit := range got {
		if hit != "GET /" && hit != "GET /version" {
			t.Errorf("confirmation sent %q: only a GET of / or of the documented /version is allowed", hit)
		}
	}
	byID := map[string]string{}
	for _, l := range leads {
		byID[l.AdvisoryID] = l.Confidence + "|" + l.Read
	}
	if !strings.HasPrefix(byID["CVE-TEST-0001"], "observed|") || !strings.Contains(byID["CVE-TEST-0001"], "inside the advisory's range") {
		t.Errorf("plain lead %q, want observed", byID["CVE-TEST-0001"])
	}
	if !strings.HasPrefix(byID["CVE-TEST-0002"], "inferred|") || !strings.Contains(byID["CVE-TEST-0002"], "example module") {
		t.Errorf("conditional lead %q, want inferred naming the precondition still open", byID["CVE-TEST-0002"])
	}
	// Every confirmation read is a ledger line of this collector.
	n := 0
	if err := ledger.Read(ledPath, func(e ledger.Entry) error {
		if e.Kind == "http" && e.Collector == "azhaq-advisories" {
			n++
			if e.Method != http.MethodGet {
				t.Errorf("ledger line method %q, want GET", e.Method)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("ledger holds %d advisory reads, want 2 (one per confirmation)", n)
	}
}

// A stand-in that exposes no version signal yields claimed, never
// observed: the range match stands alone.
func TestAdvisoryStageConfirmNoSignalIsClaimed(t *testing.T) {
	egress.Reset()
	cs := newCountingServer(t, false) // states no product or version anywhere
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	leads, failures, _ := advisoryStage(context.Background(), st, portsObs(cs),
		advisoryFlags{on: true, confirm: true, source: writeAdvFixture(t, advFixture)})
	if len(failures) > 0 {
		t.Fatalf("failures %v", failures)
	}
	if len(leads) == 0 {
		t.Fatal("no leads")
	}
	for _, l := range leads {
		if l.Confidence == "observed" {
			t.Errorf("lead %+v observed with no signal read", l)
		}
		if l.Confidence != "claimed" && l.Confidence != "inferred" {
			t.Errorf("lead %+v confidence %q, want claimed or inferred", l, l.Confidence)
		}
	}
	if got := cs.requests(); len(got) == 0 {
		t.Error("confirmation read nothing at all: it should have asked and found no signal")
	}
}

// End to end on ports: the scan names nginx 1.18.0, the lead prints
// after the port rows, the confirmation reads only GET /version, and
// its read is a ledger line. The one-advisory fixture names that path,
// so the count is exact.
func TestAdvisoriesPortsConfirmEndToEnd(t *testing.T) {
	egress.Reset()
	cs := newCountingServer(t, true)
	fixture := `[{"id":"CVE-TEST-0009","summary":"old nginx issue","azhaq_confirm_path":"/version",
	  "affected":[{"package":{"name":"nginx","ecosystem":"test"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.20.0"}]}]}],
	  "references":[{"type":"ADVISORY","url":"https://example.test/CVE-TEST-0009"}]}]`
	dir := t.TempDir()
	db := filepath.Join(dir, "w.db")
	port := strconv.Itoa(cs.port())
	out, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", port, "-db", db, "-json",
			"-advisories", "-advisories-confirm", "-advisory-source", writeAdvFixture(t, fixture)})
	})
	if err != nil {
		t.Fatalf("ports: %v\n%s", err, errOut)
	}
	var leads, ports int
	for _, line := range strings.Split(out, "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		switch row["type"] {
		case "advisory":
			leads++
			if row["label"] != "affected" || row["confidence"] != "observed" || row["advisory_id"] != "CVE-TEST-0009" {
				t.Errorf("lead line %s, want affected/observed CVE-TEST-0009", line)
			}
		default:
			if _, ok := row["port"]; ok {
				ports++
			}
		}
	}
	if leads != 1 || ports != 1 {
		t.Fatalf("stdout: %d advisory lines, %d port rows, want 1 and 1:\n%s", leads, ports, out)
	}
	rep := lastReport(t, errOut)
	if rep.Results != 1 || rep.Counts["advisory leads"] != 1 || len(rep.Advisories) != 1 {
		// ports counts its own results (the port alone); the leads are
		// counted apart in counts, printed above, and held in the
		// summary's advisories, one per line printed.
		t.Fatalf("summary results=%d counts=%v advisories=%v, want the port alone in results and 1 advisory lead in counts", rep.Results, rep.Counts, rep.Advisories)
	}
	versionReads := 0
	for _, hit := range cs.requests() {
		if hit == "GET /version" {
			versionReads++
		}
		if !strings.HasPrefix(hit, "GET ") && !strings.HasPrefix(hit, "HEAD ") {
			t.Errorf("the scan and confirmation sent %q: only reads are allowed", hit)
		}
	}
	if versionReads != 1 {
		t.Fatalf("confirmation sent %d GET /version reads, want 1: %v", versionReads, cs.requests())
	}
	// The confirmation read is in the run's ledger, as azhaq-advisories.
	n := 0
	ledPath := db + ".ledger.jsonl"
	if err := ledger.Read(ledPath, func(e ledger.Entry) error {
		if e.Kind == "http" && e.Collector == "azhaq-advisories" && strings.Contains(e.Target, "/version") {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("ledger holds %d advisory /version reads, want 1", n)
	}
}

// A failed advisory fetch is a failure of the stage (the caller makes
// it exit 3), never silence that reads as no matches.
func TestAdvisoryStageBadSourceFails(t *testing.T) {
	egress.Reset()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	leads, failures, _ := advisoryStage(context.Background(), st, nil,
		advisoryFlags{on: true, source: filepath.Join(t.TempDir(), "missing.json")})
	if leads != nil || len(failures) != 1 {
		t.Fatalf("leads %v failures %v, want one failure and no leads", leads, failures)
	}
	if err := (advisoryFlags{on: true, confirm: true}).check(); err != nil {
		t.Errorf("-advisories-confirm needs no source of yours: the built-in index is one: %v", err)
	}
	if err := (advisoryFlags{confirm: true, source: "x.json"}).check(); err == nil {
		t.Error("-advisories-confirm without -advisories checked clean")
	}
	if err := (advisoryFlags{source: "x.json"}).check(); err == nil {
		t.Error("-advisory-source with -advisories=false checked clean")
	}
}

// End to end on run: the product the HTTP answer names is matched, the
// lead is a -json line and a summary advisory, and no confirmation read
// is sent without -advisories-confirm.
func TestAdvisoriesRunEndToEnd(t *testing.T) {
	egress.Reset()
	cs := newCountingServer(t, true)
	db := filepath.Join(t.TempDir(), "w.db")
	out, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", cs.URL + "/", "-db", db, "-json", "-depth", "0",
			"-no-paths", "-no-tech", "-no-favicon",
			"-advisories", "-advisory-source", writeAdvFixture(t, advFixture)})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, errOut)
	}
	var leadLines int
	for _, line := range strings.Split(out, "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil || row["type"] != "advisory" {
			continue
		}
		leadLines++
		if row["advisory_id"] == "CVE-TEST-0001" {
			if row["label"] != "affected" || row["version_seen"] != "1.18.0" || row["url"] != "https://example.test/CVE-TEST-0001" {
				t.Errorf("lead line %s", line)
			}
			if _, ok := row["confidence"]; ok {
				t.Errorf("lead line carries a confidence without confirmation: %s", line)
			}
		}
	}
	if leadLines != 2 {
		t.Fatalf("stdout holds %d advisory lines, want 2:\n%s", leadLines, out)
	}
	rep := lastReport(t, errOut)
	if len(rep.Advisories) != 2 {
		t.Fatalf("summary advisories %+v, want 2", rep.Advisories)
	}
	for _, hit := range cs.requests() {
		if hit == "GET /version" {
			t.Fatalf("Part 1 sent a confirmation read: %v", cs.requests())
		}
	}
}
