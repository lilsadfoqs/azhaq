package portscan

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseRowStrictRejectsAnUnknownKey(t *testing.T) {
	raw := json.RawMessage(`{"host":"a","ip":"10.0.0.1","scanned":2,"open":[80],"services":[{"port":80,"service":"http"}],"brand_new":1}`)
	if _, err := ParseRowStrict(raw); err == nil {
		t.Fatal("an unknown key was accepted")
	}
	r, err := ParseRow(raw)
	if err != nil || r.IP != "10.0.0.1" || !slices.Equal(r.Open, []int{80}) || len(r.Services) != 1 || r.Services[0].Port != 80 {
		t.Errorf("lenient read: %+v %v", r, err)
	}
	if _, err := ParseRowStrict(json.RawMessage(`{"services":[{"port":80,"nope":true}]}`)); err == nil {
		t.Error("an unknown key of a service was accepted")
	}
}

// naabu lines are imported as rows whose open list holds strings.
func TestRowReadsAnImportedOpenList(t *testing.T) {
	r, err := ParseRowStrict(json.RawMessage(`{"host":"a","ip":"10.0.0.1","open":["80"],"services":[{"port":80}],"via":"naabu"}`))
	if err != nil || !slices.Equal(r.Open, []int{80}) || r.Via != "naabu" {
		t.Errorf("%+v %v", r, err)
	}
	if _, err := ParseRow(json.RawMessage(`{"open":["http"]}`)); err == nil {
		t.Error("a name in the open list was read as a port")
	}
	r, err = ParseRow(json.RawMessage(`{"open":null}`))
	if err != nil || r.Open != nil {
		t.Errorf("null open: %+v %v", r, err)
	}
}

// TestReplayedRowsFitRow decodes every ports row of the recorded workspaces
// under AZHAQ_REPLAY_DIR strictly. They stay out of the repository (they name a
// target); without the variable the test is skipped.
func TestReplayedRowsFitRow(t *testing.T) {
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
	rows, other, bad := 0, 0, 0
	for _, p := range exports {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			var line struct {
				Kind        string `json:"kind"`
				Collector   string `json:"collector"`
				ObsKind     string `json:"obs_kind"`
				Payload     json.RawMessage
				Observation struct {
					Collector string          `json:"collector"`
					Kind      string          `json:"kind"`
					Payload   json.RawMessage `json:"payload"`
				} `json:"observation"`
			}
			line.Payload = nil
			if json.Unmarshal(sc.Bytes(), &line) != nil || line.Kind != "observation" {
				continue
			}
			collector, kind, payload := line.Observation.Collector, line.Observation.Kind, line.Observation.Payload
			if collector == "" { // the flat form of a line
				collector, kind, payload = line.Collector, line.ObsKind, line.Payload
			}
			if collector != "azhaq-ports" {
				continue
			}
			if kind != "ports" {
				other++
				continue
			}
			rows++
			if _, err := ParseRowStrict(payload); err != nil {
				bad++
				if bad <= 5 {
					rel, _ := filepath.Rel(dir, p)
					t.Errorf("%s: %v", filepath.Dir(rel), err)
				}
			}
		}
		if err := sc.Err(); err != nil {
			t.Error(err)
		}
		f.Close()
	}
	if rows == 0 {
		t.Fatalf("no azhaq-ports row in %d exports", len(exports))
	}
	t.Logf("%d azhaq-ports rows in %d exports decode strictly (%d bad); %d other azhaq-ports observations", rows-bad, len(exports), bad, other)
}
