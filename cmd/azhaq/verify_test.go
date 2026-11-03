package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// redisFixture is a raw TCP stand-in: it answers every request with
// resp and records the exact requests it was sent.
type redisFixture struct {
	port int
	mu   sync.Mutex
	reqs []string
}

func newRedisFixture(t *testing.T, resp string) *redisFixture {
	t.Helper()
	f := &redisFixture{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				f.mu.Lock()
				f.reqs = append(f.reqs, string(buf[:n]))
				f.mu.Unlock()
				_, _ = c.Write([]byte(resp))
			}(c)
		}
	}()
	return f
}

func (f *redisFixture) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *redisFixture) infoCount() int {
	n := 0
	for _, r := range f.requests() {
		if strings.Contains(r, "INFO server") {
			n++
		}
	}
	return n
}

const redisInfoBody = "# Server\r\nredis_version:7.2.0\r\nredis_mode:standalone\r\n"

func redisInfoResp() string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(redisInfoBody), redisInfoBody)
}

func redisObs(port int, version string) []types.StoredObservation {
	raw, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "ip": "127.0.0.1",
		"services": []map[string]any{{"port": port, "service": "redis", "product": "Redis", "version": version}},
	})
	return []types.StoredObservation{{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}}}
}

// The unauthenticated fixture is proved; the one that asks for a
// credential is version-only, never proved. Each sends exactly one
// INFO server and each connect is a ledger line of azhaq-verify.
func TestVerifyStageRedisWithAndWithoutAuth(t *testing.T) {
	egress.Reset()
	unauth := newRedisFixture(t, redisInfoResp())
	auth := newRedisFixture(t, "-NOAUTH Authentication required.\r\n")
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
	obs := append(redisObs(unauth.port, ""), redisObs(auth.port, "7.2.0")...)
	results, failures, note := verifyStage(context.Background(), st, obs, nil, "azhaq run -verify")
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 {
		t.Fatalf("failures %v", failures)
	}
	byPort := map[int]verify.Result{}
	for _, r := range results {
		byPort[r.Port] = r
	}
	if r := byPort[unauth.port]; r.Label != verify.Proved || r.Version != "7.2.0" || r.Request != "INFO server" {
		t.Errorf("unauthenticated fixture: %+v, want proved Redis 7.2.0 by INFO server", r)
	}
	if r := byPort[auth.port]; r.Label != verify.VersionOnly {
		t.Errorf("authenticated fixture: %+v, want version-only, never proved", r)
	}
	if unauth.infoCount() != 1 || auth.infoCount() != 1 {
		t.Errorf("INFO reads: unauth %d, auth %d, want exactly 1 each", unauth.infoCount(), auth.infoCount())
	}
	if !strings.Contains(note, "2 results (1 proved, 1 version-only, 0 conditional)") {
		t.Errorf("note %q does not count the results printed", note)
	}
	n := 0
	if err := ledger.Read(ledPath, func(e ledger.Entry) error {
		if e.Kind == "tcp" && e.Collector == "azhaq-verify" {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("ledger holds %d azhaq-verify connects, want 2", n)
	}
	// The results are stored rows, so the counts derive from them.
	stored, _ := st.Observations()
	if got := verifyResultsOf(stored); len(got) != len(results) {
		t.Errorf("stored verify results %d, printed %d", len(got), len(results))
	}
}

// The request budget stops a verification read like any other: it is
// a note, not a failure, and nothing more is sent.
func TestVerifyStageBudgetStopsReads(t *testing.T) {
	egress.Reset()
	fx := newRedisFixture(t, redisInfoResp())
	other := newRedisFixture(t, redisInfoResp())
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// One request of budget, two services: one read, one stopped.
	egress.Current().SetMaxRequests(1)
	obs := append(redisObs(fx.port, ""), redisObs(other.port, "")...)
	results, failures, note := verifyStage(context.Background(), st, obs, nil, "azhaq run -verify")
	if len(failures) > 0 || len(results) != 1 || !strings.Contains(note, "the run's limit stopped them") {
		t.Fatalf("results %v failures %v note %q", results, failures, note)
	}
	// Spent from the start: no read at all.
	egress.Reset()
	egress.Current().SetMaxRequests(1)
	_ = egress.Take()
	results, failures, note = verifyStage(context.Background(), st, redisObs(fx.port, ""), nil, "azhaq run -verify")
	if len(failures) > 0 || len(results) != 0 || !strings.Contains(note, "the run's limit stopped them") {
		t.Fatalf("spent budget: results %v failures %v note %q", results, failures, note)
	}
}

// End to end on ports: the scan names Redis, -verify sends one more
// INFO and prints a proved result after the port rows.
func TestVerifyPortsEndToEnd(t *testing.T) {
	egress.Reset()
	fx := newRedisFixture(t, redisInfoResp())
	dir := t.TempDir()
	db := filepath.Join(dir, "w.db")
	out, errOut, err := captureBoth(t, func() error {
		return cmdPorts([]string{"-host", "127.0.0.1", "-p", strconv.Itoa(fx.port), "-db", db, "-json", "-verify"})
	})
	if err != nil {
		t.Fatalf("ports: %v\n%s", err, errOut)
	}
	var verifyLines, portLines int
	for _, line := range strings.Split(out, "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		switch row["type"] {
		case "verify":
			verifyLines++
			if row["label"] != "proved" || row["request"] != "INFO server" || row["product"] != "Redis" {
				t.Errorf("verify line %s, want proved Redis by INFO server", line)
			}
			if ev, _ := row["evidence"].(string); !strings.Contains(ev, "redis_version:7.2.0") {
				t.Errorf("verify line evidence %q", ev)
			}
		default:
			if _, ok := row["port"]; ok {
				portLines++
			}
		}
	}
	if verifyLines != 1 || portLines != 1 {
		t.Fatalf("stdout: %d verify lines, %d port rows, want 1 and 1:\n%s", verifyLines, portLines, out)
	}
	rep := lastReport(t, errOut)
	if rep.Counts["verify results"] != 1 || len(rep.Verify) != 1 {
		t.Fatalf("summary counts=%v verify=%v, want 1 stored verify result", rep.Counts, rep.Verify)
	}
	// The verify connect is in the run's ledger, as azhaq-verify.
	n := 0
	if err := ledger.Read(db+".ledger.jsonl", func(e ledger.Entry) error {
		if e.Kind == "tcp" && e.Collector == "azhaq-verify" {
			n++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("ledger holds %d azhaq-verify connects, want 1", n)
	}
}

// A -deny-path rule keeps the advisory confirmation GET out: the lead
// stays claimed, the verify result is version-only, nothing is sent to
// that path, and the exit is 0 (the rule is the user's).
func TestVerifyDenyPathKeepsConfirmationOut(t *testing.T) {
	egress.Reset()
	cs := newCountingServer(t, true)
	db := filepath.Join(t.TempDir(), "w.db")
	_, errOut, err := captureBoth(t, func() error {
		return cmdRun([]string{"-url", cs.URL + "/", "-db", db, "-json", "-depth", "0",
			"-no-paths", "-no-tech", "-no-favicon", "-deny-path", "^/version$",
			"-advisories", "-advisories-confirm", "-advisory-source", writeAdvFixture(t, advFixture),
			"-verify"})
	})
	if err != nil {
		t.Fatalf("run: %v\n%s (a -deny-path refusal must not fail the run)", err, errOut)
	}
	for _, hit := range cs.requests() {
		if hit == "GET /version" {
			t.Fatalf("the denied confirmation was sent: %v", cs.requests())
		}
	}
	rep := lastReport(t, errOut)
	var conditionalOrVersionOnly bool
	for _, r := range rep.Verify {
		if r.AdvisoryID == "CVE-TEST-0002" && r.Label != verify.Proved {
			conditionalOrVersionOnly = true
		}
		if r.Label == verify.Proved && r.AdvisoryID == "CVE-TEST-0002" {
			t.Errorf("a denied precondition read labelled proved: %+v", r)
		}
	}
	if !conditionalOrVersionOnly {
		t.Errorf("verify results %+v, want the conditional advisory kept unproved", rep.Verify)
	}
	joined := strings.Join(rep.Notes, " ")
	if !strings.Contains(joined, "-deny-path") {
		t.Errorf("notes do not name the -deny-path refusal: %q", joined)
	}
}
