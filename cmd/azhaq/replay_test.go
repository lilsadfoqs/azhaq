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
		ID   string `json:"id"`
		Type string `json:"type"`
		Key  string `json:"key"`
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
			ents[line.Entity.ID] = line.Entity
		case "observation":
			pending = append(pending, replayRow{obs: line.Observation.Observation})
			ids = append(ids, line.Observation.EntityID)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	var out []replayRow
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
