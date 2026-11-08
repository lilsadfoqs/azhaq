package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/runs"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// keptDemoRun runs the built-in demo map with runs kept in a fresh home
// and returns the home and the run's record.
func keptDemoRun(t *testing.T, args ...string) (string, runs.Record) {
	t.Helper()
	t.Cleanup(egress.Reset)
	home := t.TempDir()
	t.Setenv("AZHAQ_HOME", home)
	t.Chdir(t.TempDir())
	if err := run(append([]string{"run", "-demo", "-quiet"}, args...)); err != nil {
		t.Fatalf("run -demo: %v", err)
	}
	list, err := runs.List(home)
	if err != nil || len(list) != 1 {
		t.Fatalf("runs kept: %v %v", list, err)
	}
	return home, list[0]
}

func TestRunHomeKeepsTheWorkspaceInTheRunFolder(t *testing.T) {
	home, rec := keptDemoRun(t)
	dir := filepath.Join(runs.Dir(home), rec.ID)
	if rec.Workspace != filepath.Join(dir, runs.WorkspaceFile) {
		t.Fatalf("workspace %q, want it in %s", rec.Workspace, dir)
	}
	if _, err := os.Stat(rec.Workspace); err != nil {
		t.Fatal(err)
	}
	if rec.Status != runs.StatusDone || rec.Exit == nil || *rec.Exit != exitOK || len(rec.Summary) == 0 {
		t.Fatalf("record %+v", rec)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("run folder mode %v %v", fi.Mode(), err)
	}
	if m, _ := filepath.Glob("azhaq-*.db"); len(m) > 0 {
		t.Fatalf("a workspace was still made in the current directory: %v", m)
	}
	if m, _ := filepath.Glob(".azhaq-*"); len(m) > 0 {
		t.Fatalf("files left in the current directory: %v", m)
	}
	if got := readLastDB(); got != rec.Workspace {
		t.Fatalf("last run %q, want %q", got, rec.Workspace)
	}
}

func TestRunHomeNoneKeepsTheOldPlace(t *testing.T) {
	t.Cleanup(egress.Reset)
	t.Setenv("AZHAQ_HOME", "none")
	t.Chdir(t.TempDir())
	if err := run([]string{"run", "-demo", "-quiet"}); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob("azhaq-*.db"); len(m) != 1 {
		t.Fatalf("want the workspace in the current directory, got %v", m)
	}
}

func TestRunHomeUsageErrorLeavesNoFolder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AZHAQ_HOME", home)
	t.Chdir(t.TempDir())
	err := run([]string{"run", "-no-such-flag"})
	if exitCode(err) != exitUsage {
		t.Fatalf("want a usage error, got %v", err)
	}
	if list, _ := runs.List(home); len(list) != 0 {
		t.Fatalf("a refused command left a run: %+v", list)
	}
}

func TestRunsListsAndRemoves(t *testing.T) {
	home, rec := keptDemoRun(t)
	if err := cmdRuns([]string{"-home", home}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRuns([]string{"-home", home, "-rm", "../x"}); err == nil {
		t.Fatal("removed a folder outside the run home")
	}
	if err := cmdRuns([]string{"-home", home, "-rm", rec.ID}); err != nil {
		t.Fatal(err)
	}
	if list, _ := runs.List(home); len(list) != 0 {
		t.Fatalf("still kept: %+v", list)
	}
}

func uiGet(t *testing.T, h http.Handler, path string, v any) int {
	t.Helper()
	req := httptest.NewRequest("GET", "http://127.0.0.1:7190"+path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if v != nil && w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
			t.Fatalf("%s: %v: %s", path, err, w.Body.String())
		}
	}
	return w.Code
}

// The page's numbers are the run's own: the graph holds every entity of the
// run's workspace, and the ledger count is the summary's request count.
func TestUIGraphAndLedgerAreTheRunsOwn(t *testing.T) {
	home, rec := keptDemoRun(t)
	h := uiHandler(home)
	var list struct{ Runs []uiRunRow }
	if uiGet(t, h, "/api/runs", &list) != 200 || len(list.Runs) != 1 || list.Runs[0].ID != rec.ID {
		t.Fatalf("runs %+v", list)
	}
	var one struct {
		Ledger *uiLedger
		Status string
	}
	if uiGet(t, h, "/api/runs/"+rec.ID, &one) != 200 || one.Ledger == nil {
		t.Fatalf("run %+v", one)
	}
	var sum struct{ Requests int }
	_ = json.Unmarshal(rec.Summary, &sum)
	if one.Ledger.ByClass["target"] != sum.Requests || sum.Requests == 0 {
		t.Fatalf("ledger counts %d requests to targets, the summary %d", one.Ledger.ByClass["target"], sum.Requests)
	}
	var g struct {
		Nodes []uiGraphNode
		Edges []uiGraphEdge
	}
	if uiGet(t, h, "/api/runs/"+rec.ID+"/graph", &g) != 200 {
		t.Fatal("graph")
	}
	st, err := store.OpenExisting(rec.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	st.Close()
	if len(g.Nodes) != len(ents) || len(ents) == 0 {
		t.Fatalf("graph has %d nodes, the workspace %d entities", len(g.Nodes), len(ents))
	}
	var node struct {
		Entity       map[string]any
		Observations []any
	}
	if uiGet(t, h, "/api/runs/"+rec.ID+"/node/"+g.Nodes[0].ID, &node) != 200 || node.Entity == nil {
		t.Fatalf("node %+v", node)
	}
}

func TestUIRefusesOtherHostsAndPaths(t *testing.T) {
	home, _ := keptDemoRun(t)
	h := uiHandler(home)
	req := httptest.NewRequest("GET", "http://127.0.0.1:7190/api/runs", nil)
	req.Host = "attacker.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request naming another host got %d", w.Code)
	}
	for _, p := range []string{"/api/runs/..%2F..%2Fetc", "/api/runs/..", "/api/runs/nope/graph"} {
		if code := uiGet(t, h, p, nil); code == http.StatusOK {
			t.Errorf("%s answered 200", p)
		}
	}
}

func TestUIRefusesANonLoopbackAddress(t *testing.T) {
	t.Setenv("AZHAQ_HOME", t.TempDir())
	if err := cmdUI([]string{"-listen", "0.0.0.0:0"}); exitCode(err) != exitUsage {
		t.Fatalf("want a usage error, got %v", err)
	}
}

// The page is embedded and loads nothing from anywhere else.
func TestUINothingExternalInThePage(t *testing.T) {
	err := fs.WalkDir(uiWeb, "uiweb", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, _ := uiWeb.ReadFile(p)
		for _, bad := range []string{"http://", "https://", "//cdn", "@import"} {
			if strings.Contains(string(raw), bad) {
				return errors.New(p + " names " + bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:7190/", nil)
	w := httptest.NewRecorder()
	uiHandler(t.TempDir()).ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("page %d, csp %q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("the ui made a request to %s", r.URL)
	return nil, errors.New("no requests")
}

// Serving every view sends nothing: no request through the default
// client, nothing counted by the egress chokepoint.
func TestUISendsNothingToAnyTarget(t *testing.T) {
	home, rec := keptDemoRun(t)
	passiveCollectors() // built before the swap: making the collectors reads the default transport
	old := http.DefaultTransport
	http.DefaultTransport = failTransport{t}
	t.Cleanup(func() { http.DefaultTransport = old })
	before, dns := egress.Total(), egress.DNSTotal()
	h := uiHandler(home)
	var g struct{ Nodes []uiGraphNode }
	for _, p := range []string{"/", "/app.js", "/app.css", "/api/runs", "/api/runs/" + rec.ID, "/api/runs/" + rec.ID + "/graph"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:7190"+p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
		if strings.HasSuffix(p, "/graph") {
			_ = json.Unmarshal(w.Body.Bytes(), &g)
		}
		_, _ = io.Copy(io.Discard, w.Body)
	}
	for _, n := range g.Nodes {
		uiGet(t, h, "/api/runs/"+rec.ID+"/node/"+n.ID, nil)
	}
	if egress.Total() != before || egress.DNSTotal() != dns {
		t.Fatalf("egress counted %d requests and %d DNS queries", egress.Total()-before, egress.DNSTotal()-dns)
	}
}

func TestUIMarksFindingsLeadsAndHints(t *testing.T) {
	nodes := []uiGraphNode{{Type: "URL", Key: "https://a.test/x"}, {Type: "Hostname", Key: "b.test"}, {Type: "URL", Key: "https://a.test/y"}, {Type: "URL", Key: "https://a.test/z"}}
	byKey := map[string]int{}
	for i, n := range nodes {
		byKey[n.Type+"\x00"+n.Key] = i
	}
	markFinding(nodes, byKey, findingRecord{Label: "proved", Severity: "high", URL: "https://a.test/x"})
	markFinding(nodes, byKey, findingRecord{Label: "lead", Severity: "medium", Host: "b.test"})
	markFinding(nodes, byKey, findingRecord{Label: "lead", Severity: "info", URL: "https://a.test/y", Evidence: "archived"})
	markFinding(nodes, byKey, findingRecord{Label: "lead", Severity: "info", URL: "https://a.test/x", Evidence: "archived"})
	if nodes[0].Lead != "proved" || nodes[1].Lead != "lead" || nodes[2].Lead != "" || nodes[2].Hint != "archived" || nodes[3].Lead != "" || nodes[3].Hint != "" {
		t.Fatalf("%+v", nodes)
	}
}

// An entity every observation of which came from a third-party source is
// passive; one a request to a target saw is not.
func TestUIMarksPassiveOnlyEntities(t *testing.T) {
	home := t.TempDir()
	r, err := runs.Start(home, "run", []string{"-domain", "a.test"}, version)
	if err != nil {
		t.Fatal(err)
	}
	var passive string
	for n := range passiveCollectors() {
		if passive == "" || n < passive {
			passive = n
		}
	}
	if passive == "" {
		t.Fatal("no passive collector in the catalog")
	}
	db := filepath.Join(r.Dir, runs.WorkspaceFile)
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BeginRun("r1", 1, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for key, col := range map[string]string{"third.a.test": passive, "seen.a.test": "azhaq-http"} {
		e, err := st.UpsertEntity(types.TypeHostname, key, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.AddObservation(e.ID, types.Observation{Collector: col, Source: "x", Kind: "k", Payload: []byte(`{}`), Confidence: 1, ObservedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	r.SetSummary([]byte(`{"run_id":"r1","requests":0}`), db, nil)
	_ = r.Finish(0, "")
	var g struct{ Nodes []uiGraphNode }
	if uiGet(t, uiHandler(home), "/api/runs/"+filepath.Base(r.Dir)+"/graph", &g) != 200 || len(g.Nodes) != 2 {
		t.Fatalf("%+v", g)
	}
	for _, n := range g.Nodes {
		if n.Passive != (n.Key == "third.a.test") {
			t.Errorf("%s passive=%v", n.Key, n.Passive)
		}
	}
}

// A command that only reads or serves keeps no run folder.
func TestRunHomeSkipsReadOnlyCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AZHAQ_HOME", home)
	t.Chdir(t.TempDir())
	_ = run([]string{"query", "-db", "missing.db"})
	_ = run([]string{"runs"})
	_ = run([]string{"version"})
	if list, _ := runs.List(home); len(list) != 0 {
		t.Fatalf("kept: %+v", list)
	}
	for _, c := range commands {
		switch c.group {
		case groupMap, groupDropIn:
			if !recordedCommands[c.name] && c.name != "plan" && c.name != "scope" && c.name != "report" && c.name != "notify" {
				t.Errorf("%s sends to targets but is not kept", c.name)
			}
		}
	}
}

// A run that died before its summary shows no number it does not have.
func TestRunsSaysNotRecorded(t *testing.T) {
	s := runSummaryOf(runs.Record{})
	if s.requestsText() != "not recorded" || s.gotText() != "not recorded" {
		t.Fatalf("%q %q", s.requestsText(), s.gotText())
	}
	if st := runStatus(runs.Record{Status: runs.StatusRunning, Pid: -1}); st != "did not finish" {
		t.Fatalf("status %q", st)
	}
}
