package main

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// replayRows reads the observations of a workspace export (azhaq export
// -format jsonl) with the type and key of their entity.
type replayRow struct {
	typ types.SeedType
	key string
	obs types.Observation
}

func replayRows(t *testing.T, path string) []replayRow {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type ent struct {
		ID        string    `json:"id"`
		Type      string    `json:"type"`
		Key       string    `json:"key"`
		FirstSeen time.Time `json:"first_seen"`
	}
	var line struct {
		Kind        string `json:"kind"`
		Entity      ent    `json:"entity"`
		Observation struct {
			EntityID string `json:"entity_id"`
			types.Observation
		} `json:"observation"`
	}
	ents := map[string]ent{}
	var order []string // entity ids in file order
	var pending []replayRow
	var ids []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line.Kind, line.Entity, line.Observation.EntityID, line.Observation.Observation = "", ent{}, "", types.Observation{}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		switch line.Kind {
		case "entity":
			if _, ok := ents[line.Entity.ID]; !ok {
				order = append(order, line.Entity.ID)
			}
			ents[line.Entity.ID] = line.Entity
		case "observation":
			pending = append(pending, replayRow{obs: line.Observation.Observation})
			ids = append(ids, line.Observation.EntityID)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	// An entity no observation names (a URL a page links to) is a row of its
	// own, with no collector: it is part of what a run knows.
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	var out []replayRow
	for _, id := range order {
		if e := ents[id]; !seen[id] {
			out = append(out, replayRow{typ: types.SeedType(e.Type), key: e.Key, obs: types.Observation{ObservedAt: e.FirstSeen}})
		}
	}
	for i, r := range pending {
		e, ok := ents[ids[i]]
		if !ok {
			continue
		}
		r.typ, r.key = types.SeedType(e.Type), e.Key
		out = append(out, r)
	}
	return out
}

func replayRun(t *testing.T, st *store.Store, id string, rows []replayRow) {
	t.Helper()
	if err := st.BeginRun(id, 0, 0); err != nil {
		t.Fatal(err)
	}
	var err error
	st.Batch(func() {
		for _, r := range rows {
			var e types.Entity
			if e, err = st.UpsertEntity(r.typ, r.key, r.obs.ObservedAt); err != nil {
				return
			}
			if r.obs.Collector == "" {
				continue
			}
			if _, err = st.AddObservation(e.ID, r.obs); err != nil {
				return
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestReplayRecordedWorkspaces runs watch's comparison on the row shapes of
// real runs (#491): each workspace export under AZHAQ_REPLAY_DIR is stored as
// two runs of one workspace, the second with its rows in reverse order, and
// nothing may have changed between them. Recorded workspaces stay out of the
// repository (they name a target); without the variable the test is skipped.
func TestReplayRecordedWorkspaces(t *testing.T) {
	dir := os.Getenv("AZHAQ_REPLAY_DIR")
	if dir == "" {
		t.Skip("AZHAQ_REPLAY_DIR names no folder of recorded workspace exports")
	}
	var exports []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "export.jsonl" {
			exports = append(exports, p)
		}
		return nil
	})
	if len(exports) == 0 {
		t.Fatalf("no export.jsonl under %s", dir)
	}
	for _, p := range exports {
		rel, _ := filepath.Rel(dir, p)
		t.Run(filepath.Dir(rel), func(t *testing.T) {
			rows := replayRows(t, p)
			db := filepath.Join(t.TempDir(), "ws.db")
			st, err := store.Open(db)
			if err != nil {
				t.Fatal(err)
			}
			replayRun(t, st, "first", rows)
			time.Sleep(2 * time.Millisecond) // runs are ordered by start time
			back := slices.Clone(rows)
			slices.Reverse(back)
			replayRun(t, st, "second", back)
			st.Close()
			ch, err := diffRuns(db)
			if err != nil {
				t.Fatal(err)
			}
			if ch.any() {
				t.Errorf("%d rows: the same rows in another order changed: %s", len(rows), ch.notifyText(5))
			}
		})
	}
}

// withoutPort is the rows with port p closed at address ip: gone from the
// open set and the services of every ports row of the address.
func withoutPort(t *testing.T, rows []replayRow, ip string, p int) []replayRow {
	t.Helper()
	out := make([]replayRow, 0, len(rows))
	for _, r := range rows {
		if r.obs.Collector == "azhaq-ports" {
			var m map[string]any
			if json.Unmarshal(r.obs.Payload, &m) == nil && m["ip"] == ip {
				if open, ok := m["open"].([]any); ok {
					m["open"] = slices.DeleteFunc(open, func(x any) bool { n, _ := x.(float64); return int(n) == p })
				}
				if svcs, ok := m["services"].([]any); ok {
					m["services"] = slices.DeleteFunc(svcs, func(x any) bool {
						s, _ := x.(map[string]any)
						n, _ := s["port"].(float64)
						return int(n) == p
					})
				}
				raw, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				r.obs.Payload = raw
			}
		}
		out = append(out, r)
	}
	return out
}

// openAt is the addresses with an open TCP port in finished scans of the rows,
// with one such port each, in order.
func openAt(rows []replayRow) (ips []string, port map[string]int) {
	port = map[string]int{}
	for _, r := range rows {
		if r.obs.Collector != "azhaq-ports" {
			continue
		}
		var row struct {
			IP      string `json:"ip"`
			Partial bool   `json:"partial"`
			Open    []int  `json:"open"`
		}
		if json.Unmarshal(r.obs.Payload, &row) != nil || row.IP == "" || row.Partial || len(row.Open) == 0 {
			continue
		}
		if _, ok := port[row.IP]; !ok {
			ips = append(ips, row.IP)
			port[row.IP] = row.Open[len(row.Open)-1]
		}
	}
	return ips, port
}

// TestReplayANewPortIsNamedAtItsAddress closes one port of an address in the
// first of two runs of a recorded workspace (#491): the change set must say
// the port opened, on a line that names the address, whichever seed (a name,
// the address, a range) scanned it, and say nothing else about ports.
func TestReplayANewPortIsNamedAtItsAddress(t *testing.T) {
	dir := os.Getenv("AZHAQ_REPLAY_DIR")
	if dir == "" {
		t.Skip("AZHAQ_REPLAY_DIR names no folder of recorded workspace exports")
	}
	var exports []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "export.jsonl" {
			exports = append(exports, p)
		}
		return nil
	})
	for _, p := range exports {
		rel, _ := filepath.Rel(dir, p)
		rows := replayRows(t, p)
		ips, port := openAt(rows)
		if len(ips) > 3 {
			ips = ips[:3]
		}
		for _, ip := range ips {
			t.Run(filepath.Dir(rel)+"/"+ip, func(t *testing.T) {
				db := filepath.Join(t.TempDir(), "ws.db")
				st, err := store.Open(db)
				if err != nil {
					t.Fatal(err)
				}
				replayRun(t, st, "first", withoutPort(t, rows, ip, port[ip]))
				time.Sleep(2 * time.Millisecond)
				replayRun(t, st, "second", rows)
				st.Close()
				ch, err := diffRuns(db)
				if err != nil {
					t.Fatal(err)
				}
				want := "+" + strconv.Itoa(port[ip]) + "/tcp"
				if len(ch.Ports) != 1 || !strings.Contains(ch.Ports[0], want) ||
					!(strings.HasPrefix(ch.Ports[0], ip+":") || strings.Contains(ch.Ports[0], "("+ip+")")) {
					t.Errorf("port %d opened at %s: ports lines %q", port[ip], ip, ch.Ports)
				}
			})
		}
	}
}

// pairProblems stores two runs of one target as the runs of one workspace and
// returns what watch and diff report between them, one string each. Nothing is
// filtered: when the target did not change, the lists are empty, and whatever
// is left is either a false change or a difference of the runs to be judged.
func pairProblems(t *testing.T, first, second []replayRow) (watch, diff []string) {
	t.Helper()
	db := filepath.Join(t.TempDir(), "ws.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	replayRun(t, st, "run1", first)
	time.Sleep(2 * time.Millisecond) // runs are ordered by start time
	replayRun(t, st, "run2", second)
	st.Close()

	ch, err := diffRuns(db) // what watch reports after its second run
	if err != nil {
		t.Fatal(err)
	}
	if ch.any() {
		for _, l := range strings.Split(strings.TrimSpace(ch.notifyText(0)), "\n")[1:] {
			watch = append(watch, strings.TrimSpace(l))
		}
	}

	old, err := store.OpenExisting(db) // what diff counts between them
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	neu, err := store.OpenExisting(db)
	if err != nil {
		t.Fatal(err)
	}
	defer neu.Close()
	old.UseRun("run1")
	neu.UseRun("run2")
	d, err := store.Compare(old, neu)
	if err != nil {
		t.Fatal(err)
	}
	removed, _ := splitRemoved(old, d.Removed) // names only heard of are "not seen again", not a change
	for _, e := range d.Added {
		diff = append(diff, "+ "+string(e.Type)+" "+e.Key)
	}
	for _, e := range removed {
		diff = append(diff, "- "+string(e.Type)+" "+e.Key)
	}
	oldObs, err := old.Observations()
	if err != nil {
		t.Fatal(err)
	}
	ents, err := neu.Entities()
	if err != nil {
		t.Fatal(err)
	}
	keyOf := map[string]string{}
	for _, e := range ents {
		keyOf[e.ID] = e.Key
	}
	before := map[string][]types.StoredObservation{}
	for _, o := range oldObs {
		k := o.EntityID + "\x00" + o.Collector + "\x00" + o.Kind
		before[k] = append(before[k], o)
	}
	groups := map[string][]string{}
	var names []string
	for _, o := range d.NewObs {
		k := o.Collector + " " + o.Kind
		if _, ok := groups[k]; !ok {
			names = append(names, k)
		}
		groups[k] = append(groups[k], keyOf[o.EntityID]+": "+obsDifference(before[o.EntityID+"\x00"+obsGroup(o)], o))
	}
	slices.Sort(names)
	for _, k := range names {
		ex := groups[k]
		line := strconv.Itoa(len(ex)) + " new " + k + " observations"
		for i := 0; i < len(ex) && i < 3; i++ {
			line += "\n      " + ex[i]
		}
		diff = append(diff, line)
	}
	return watch, diff
}

func obsGroup(o types.StoredObservation) string { return o.Collector + "\x00" + o.Kind }

// obsDifference says how a row of the second run differs from the rows of the
// first run about the same entity from the same collector and kind: the
// top-level fields that differ, in the closest of them, with their values.
func obsDifference(olds []types.StoredObservation, o types.StoredObservation) string {
	if len(olds) == 0 {
		return "no such row in the first run"
	}
	var neu map[string]json.RawMessage
	_ = json.Unmarshal(o.Payload, &neu)
	best, bestN := "", -1
	for _, old := range olds {
		var was map[string]json.RawMessage
		_ = json.Unmarshal(old.Payload, &was)
		var parts []string
		for k, v := range neu {
			if string(was[k]) != string(v) {
				parts = append(parts, k+" "+replayClip(string(was[k]))+" -> "+replayClip(string(v)))
			}
		}
		for k, v := range was {
			if _, ok := neu[k]; !ok {
				parts = append(parts, k+" "+replayClip(string(v))+" -> (absent)")
			}
		}
		slices.Sort(parts)
		if bestN < 0 || len(parts) < bestN {
			best, bestN = strings.Join(parts, "; "), len(parts)
		}
	}
	if bestN == 0 {
		return "the same top-level fields as a row of the first run (the difference is in the dropped volatile fields or in the order of the rows)"
	}
	return best
}

func replayClip(s string) string {
	if s == "" {
		return "(absent)"
	}
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

// replayPairs finds the run pairs under dir: a folder that holds
// export-run1.jsonl and export-run2.jsonl, the exports of the first and the
// second run of one workspace (azhaq export -run), keyed by its path in dir.
func replayPairs(dir string) map[string][2]string {
	pairs := map[string][2]string{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "export-run1.jsonl" {
			return nil
		}
		two := filepath.Join(filepath.Dir(p), "export-run2.jsonl")
		if _, err := os.Stat(two); err == nil {
			rel, _ := filepath.Rel(dir, filepath.Dir(p))
			pairs[rel] = [2]string{p, two}
		}
		return nil
	})
	return pairs
}

// checkPairs runs watch's and diff's comparison over each run pair under dir
// and fails with the lines they report.
func checkPairs(t *testing.T, dir string) {
	pairs := replayPairs(dir)
	if len(pairs) == 0 {
		t.Skipf("no run pair (export-run1.jsonl and export-run2.jsonl) under %s", dir)
	}
	for rel, p := range pairs {
		t.Run(rel, func(t *testing.T) {
			watch, diff := pairProblems(t, replayRows(t, p[0]), replayRows(t, p[1]))
			if len(watch) > 0 {
				t.Errorf("watch reports %d lines between two runs of an unchanged target:\n  %s", len(watch), strings.Join(watch, "\n  "))
			}
			if len(diff) > 0 {
				t.Errorf("diff reports %d lines between two runs of an unchanged target:\n  %s", len(diff), strings.Join(diff, "\n  "))
			}
		})
	}
}

// TestReplayRunPairsOfAnUnchangedTarget is the no-false-change invariant (#491):
// two runs of one target that did not change in between, as the lab network's
// parity run keeps them (pairs=1), give no new or gone port, service, name or
// URL, and no changed page or product, in watch or in diff. A difference that
// belongs to the runs (a session id, a time) is listed, not filtered, so it
// can be judged. Without the variable the test is skipped.
func TestReplayRunPairsOfAnUnchangedTarget(t *testing.T) {
	dir := os.Getenv("AZHAQ_REPLAY_DIR")
	if dir == "" {
		t.Skip("AZHAQ_REPLAY_DIR names no folder of recorded workspace exports")
	}
	checkPairs(t, dir)
}
