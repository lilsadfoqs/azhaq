package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMergeJoinsSectionRecords(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a.json", `{"date":"2026-10-31T12:00:00Z","commit":"abc","go":"go1","tools":[{"name":"httpx"}],
		"probe":{},"apps":[{}],"polite":{"probe":{}},
		"checks":[{"name":"probe ok","pass":true,"detail":""}],"runs":[{"tool":"httpx"}]}`)
	b := write("b.json", `{"date":"2026-10-31T11:00:00Z","commit":"abc","go":"go1","tools":[{"name":"httpx"},{"name":"ffuf"}],
		"scope":{"trap_requests":1},"polite":{"dirs":{}},
		"checks":[{"name":"scope ok","pass":false,"detail":"no"}],"runs":[{"tool":"ffuf"}]}`)
	out := filepath.Join(dir, "out")
	if err := mergeRecords([]string{a, b}, out, nil); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.json"))
	if len(files) != 1 || filepath.Base(files[0]) != "2026-10-31T110000-abc.json" {
		t.Fatalf("record files %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if n := len(got["checks"].([]any)); n != 2 {
		t.Errorf("checks %d, want 2", n)
	}
	if n := len(got["tools"].([]any)); n != 2 {
		t.Errorf("tools %d, want 2 (listed once)", n)
	}
	if got["scope"] == nil || got["probe"] == nil || got["apps"] == nil {
		t.Errorf("a section row was lost: %v", got)
	}
	p := got["polite"].(map[string]any)
	if p["probe"] == nil || p["dirs"] == nil {
		t.Errorf("polite rows not joined: %v", p)
	}
}

func TestMergeRefusesTwoCommits(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	_ = os.WriteFile(a, []byte(`{"commit":"abc","checks":[]}`), 0o644)
	_ = os.WriteFile(b, []byte(`{"commit":"def","checks":[]}`), 0o644)
	if err := mergeRecords([]string{a, b}, dir, nil); err == nil {
		t.Fatal("records of two commits were joined")
	}
}

// unitRec is a record holding what the named units wrote: each has one
// check and one run named after it, and the claims cases two rows.
func unitRec(commit string, names ...string) map[string]any {
	var checks, runs, spans, rows []any
	for _, n := range names {
		checks = append(checks, map[string]any{"name": n, "pass": true, "detail": ""})
		runs = append(runs, map[string]any{"tool": n, "target": "t", "seconds": 1.0, "rss_mb": 0.0})
		sp := map[string]any{"name": n, "checks": 1, "runs": 1}
		if strings.HasPrefix(n, "claims:") {
			rows = append(rows, map[string]any{"case": n + "a"}, map[string]any{"case": n + "b"})
			sp["rows"] = 2
		}
		spans = append(spans, sp)
	}
	r := map[string]any{"date": "2026-10-31T12:00:00Z", "commit": commit, "go": "go1", "tools": []any{map[string]any{"name": "ffuf"}},
		"checks": checks, "runs": runs, "units": spans}
	if len(rows) > 0 {
		r["claims"] = map[string]any{"rows": rows, "seconds": 10.0}
	}
	return r
}

func writeRec(t *testing.T, dir, name string, r map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(r)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func joined(t *testing.T, dir string) record {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "out", "*.json"))
	if len(files) != 1 {
		t.Fatalf("record files %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func checkNames(r record) []string {
	var out []string
	for _, c := range r.Checks {
		out = append(out, c.Name)
	}
	return out
}

// Records of any grouping of units join into what one run writes.
func TestMergeUnitsInOrderOfOneRun(t *testing.T) {
	full := []string{"default:apps", "default:dirs", "polite:dirs", "polite:notify", "once:dropin", "claims:1", "claims:5", "claims:11", "once:docs"}
	dir := t.TempDir()
	one := writeRec(t, dir, "full.json", unitRec("abc", full...))
	if err := mergeRecords([]string{one}, filepath.Join(dir, "out"), full); err != nil {
		t.Fatal(err)
	}
	want := joined(t, dir)
	if len(want.Checks) != len(full) {
		t.Fatalf("one record: %d checks, want %d", len(want.Checks), len(full))
	}
	if err := os.RemoveAll(filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	// Three jobs, units in the order each runs them, jobs in any order.
	b := writeRec(t, dir, "b.json", unitRec("abc", "default:dirs", "claims:5", "once:docs"))
	c := writeRec(t, dir, "c.json", unitRec("abc", "polite:notify", "claims:1"))
	a := writeRec(t, dir, "a.json", unitRec("abc", "default:apps", "polite:dirs", "once:dropin", "claims:11"))
	if err := mergeRecords([]string{b, c, a}, filepath.Join(dir, "out"), full); err != nil {
		t.Fatal(err)
	}
	got := joined(t, dir)
	if !slices.Equal(checkNames(got), checkNames(want)) || !slices.Equal(checkNames(got), full) {
		t.Errorf("checks %v, want %v", checkNames(got), full)
	}
	for i := range full {
		if got.Runs[i].Tool != full[i] {
			t.Errorf("run %d is %s, want %s", i, got.Runs[i].Tool, full[i])
		}
	}
	if !slices.Equal(got.Units, want.Units) {
		t.Errorf("units %v, want %v", got.Units, want.Units)
	}
	var cases []string
	for _, r := range got.Claims.Rows {
		cases = append(cases, r.Case)
	}
	if strings.Join(cases, " ") != "claims:1a claims:1b claims:5a claims:5b claims:11a claims:11b" || got.Claims.Seconds != 30 {
		t.Errorf("claims rows %v, seconds %v", cases, got.Claims.Seconds)
	}
	if len(got.Tools) != 1 {
		t.Errorf("tools %v", got.Tools)
	}
}

// A unit no record holds is a failed check at its place; the join still goes on.
func TestMergeMissingUnitFails(t *testing.T) {
	dir := t.TempDir()
	a := writeRec(t, dir, "a.json", unitRec("abc", "default:apps", "once:docs"))
	expect := []string{"default:apps", "polite:apps", "claims:3", "once:docs"}
	if err := mergeRecords([]string{a}, filepath.Join(dir, "out"), expect); err != nil {
		t.Fatal(err)
	}
	got := joined(t, dir)
	want := []string{"default:apps", "unit polite:apps: no result", "unit claims:3: no result", "once:docs"}
	if !slices.Equal(checkNames(got), want) {
		t.Fatalf("checks %v, want %v", checkNames(got), want)
	}
	for i, c := range got.Checks {
		if c.Pass != (i == 0 || i == 3) {
			t.Errorf("check %q pass = %v", c.Name, c.Pass)
		}
	}
	if got.Claims != nil {
		t.Errorf("a claims row from nothing: %+v", got.Claims)
	}
}

// Two records holding one unit would count its checks twice.
func TestMergeUnitInTwoRecordsFails(t *testing.T) {
	dir := t.TempDir()
	a := writeRec(t, dir, "a.json", unitRec("abc", "default:apps"))
	b := writeRec(t, dir, "b.json", unitRec("abc", "default:apps"))
	if err := mergeRecords([]string{a, b}, filepath.Join(dir, "out"), nil); err != nil {
		t.Fatal(err)
	}
	got := joined(t, dir)
	if len(got.Checks) != 2 || got.Checks[0].Name != "default:apps" || got.Checks[1].Pass {
		t.Fatalf("checks %+v", got.Checks)
	}
}

// Spans that do not fit the record are an error, not a guess.
func TestMergeUnitSpansMustFit(t *testing.T) {
	dir := t.TempDir()
	r := unitRec("abc", "default:apps")
	r["checks"] = []any{}
	a := writeRec(t, dir, "a.json", r)
	if err := mergeRecords([]string{a}, filepath.Join(dir, "out"), nil); err == nil {
		t.Fatal("spans longer than the checks were joined")
	}
}

// The domain rows of units that ran in other jobs join in the order of the
// domain list, in the default profile and the polite one.
func TestMergeDomainRowsOfSeparateUnits(t *testing.T) {
	dir := t.TempDir()
	rows := func(ds ...string) []any {
		var out []any
		for _, d := range ds {
			out = append(out, map[string]any{"domain": d, "azhaq_live": 1})
		}
		return out
	}
	mk := func(names []string, def, pol []any) map[string]any {
		r := unitRec("abc", names...)
		if def != nil {
			r["domains"] = def
		}
		if pol != nil {
			r["polite"] = map[string]any{"domains": pol}
		}
		return r
	}
	a := writeRec(t, dir, "a.json", mk([]string{"default:domains/vulnweb.com", "polite:domains/hackerone.com"}, rows("vulnweb.com"), rows("hackerone.com")))
	b := writeRec(t, dir, "b.json", mk([]string{"default:domains/hackerone.com", "polite:domains/vulnweb.com"}, rows("hackerone.com"), rows("vulnweb.com")))
	c := writeRec(t, dir, "c.json", mk([]string{"default:domains/tesla.com"}, rows("tesla.com"), nil))
	expect := []string{"default:domains/hackerone.com", "default:domains/tesla.com", "default:domains/vulnweb.com", "polite:domains/hackerone.com", "polite:domains/vulnweb.com"}
	if err := mergeRecords([]string{a, b, c}, filepath.Join(dir, "out"), expect); err != nil {
		t.Fatal(err)
	}
	got := joined(t, dir)
	if !slices.Equal(checkNames(got), expect) {
		t.Errorf("checks %v", checkNames(got))
	}
	names := func(rs []domainRow) string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Domain)
		}
		return strings.Join(out, " ")
	}
	if n := names(got.Domains); n != "hackerone.com tesla.com vulnweb.com" {
		t.Errorf("default domains %q", n)
	}
	if n := names(got.Polite.Domains); n != "hackerone.com vulnweb.com" {
		t.Errorf("polite domains %q", n)
	}
	// A domain no record holds is a failed check, and no row.
	if err := os.RemoveAll(filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if err := mergeRecords([]string{a, c}, filepath.Join(dir, "out"), expect); err != nil {
		t.Fatal(err)
	}
	got = joined(t, dir)
	failed := 0
	for _, ch := range got.Checks {
		if !ch.Pass {
			failed++
		}
	}
	if failed != 2 || len(got.Domains) != 2 {
		t.Errorf("%d failed checks, %d default domain rows", failed, len(got.Domains))
	}
}
