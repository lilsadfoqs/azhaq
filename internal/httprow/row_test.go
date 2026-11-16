package httprow

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

func TestParseRowStrictRejectsAnUnknownKey(t *testing.T) {
	raw := json.RawMessage(`{"url":"http://a/","status":200,"tech":["Nginx:1.2"],"detected":[{"product":"x","template":"t"}],"brand_new":1}`)
	if _, err := ParseRowStrict(raw); err == nil {
		t.Fatal("an unknown key was accepted")
	}
	r, err := ParseRow(raw)
	if err != nil || r.Status != 200 || !slices.Equal(r.Tech, []string{"Nginx:1.2"}) || len(r.Detected) != 1 || r.Detected[0].Product != "x" {
		t.Errorf("lenient read: %+v %v", r, err)
	}
	if _, err := ParseRowStrict(json.RawMessage(`{"tls":{"host":"a","nope":1}}`)); err == nil {
		t.Error("an unknown key of the tls object was accepted")
	}
	if _, err := ParseRowStrict(json.RawMessage(`{"stack_trace":{"runtime":"java","exception":"e","frames":3},"control":{"url":"u","status":404,"size":3}}`)); err != nil {
		t.Error(err)
	}
}

// The evidence keys the fetch package writes are the fields the row reads.
func TestEvidenceKeysAreFields(t *testing.T) {
	tags := tagsOf(reflect.TypeOf(Row{}))
	for _, k := range fetch.EvidenceKeys {
		if !tags[k] {
			t.Errorf("fetch.EvidenceKeys names %q, which Row has no field for", k)
		}
	}
	ev := tagsOf(reflect.TypeOf(fetch.Evidence{}))
	for k := range ev {
		if !tags[k] {
			t.Errorf("fetch.Evidence has %q, which Row has no field for", k)
		}
	}
}

func tagsOf(rt reflect.Type) map[string]bool {
	tags := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		tags[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	return tags
}

// The objects a row passes on as they are (tls, csp, knowledgebase) are written
// in the order a map of them is: a row read and written again is the same.
func TestPassedOnObjectsKeepTheirBytes(t *testing.T) {
	raw := `{"csp":{"domains":["a.com"],"fqdn":null},"knowledgebase":{"Forms":[{"a":1}],"PageType":"login","pHash":0},"tls":{"cipher":"c","emails":["e@x"],"expired":true,"fingerprint_hash":{"md5":"1","sha1":"2","sha256":"3"},"host":"h","issuer_cn":"","issuer_dn":"d","issuer_org":["o"],"mismatched":true,"not_after":"a","not_before":"b","port":"443","probe_status":true,"self_signed":true,"serial":"s","sni":"n","subject_an":["x"],"subject_cn":"c","subject_dn":"d","subject_org":["o"],"tls_connection":"ctls","tls_version":"tls13","wildcard_certificate":true}}`
	r, err := ParseRowStrict(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(r)
	var a, b any
	_ = json.Unmarshal(got, &a)
	_ = json.Unmarshal([]byte(raw), &b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("\n got %s\nwant %s", got, raw)
	}
	for _, k := range []string{"csp", "knowledgebase", "tls"} {
		var one map[string]json.RawMessage
		_ = json.Unmarshal(got, &one)
		var want map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &want)
		if string(one[k]) != string(want[k]) {
			t.Errorf("%s: %s, want %s", k, one[k], want[k])
		}
	}
}

// TestReplayedRowsFitRow decodes every azhaq-http row of the recorded
// workspaces under AZHAQ_REPLAY_DIR strictly. They stay out of the repository
// (they name a target); without the variable the test is skipped.
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
	rows, bad := 0, 0
	kinds := map[string]int{}
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
			if json.Unmarshal(sc.Bytes(), &line) != nil || line.Kind != "observation" {
				continue
			}
			collector, kind, payload := line.Observation.Collector, line.Observation.Kind, line.Observation.Payload
			if collector == "" { // the flat form of a line
				collector, kind, payload = line.Collector, line.ObsKind, line.Payload
			}
			if collector != "azhaq-http" {
				continue
			}
			rows++
			kinds[kind]++
			if _, err := ParseRowStrict(payload); err != nil {
				bad++
				if bad <= 5 {
					rel, _ := filepath.Rel(dir, p)
					t.Errorf("%s: %s row: %v", filepath.Dir(rel), kind, err)
				}
			}
		}
		if err := sc.Err(); err != nil {
			t.Error(err)
		}
		f.Close()
	}
	if rows == 0 {
		t.Fatalf("no azhaq-http row in %d exports", len(exports))
	}
	t.Logf("%d azhaq-http rows in %d exports decode strictly (%d bad); by kind %v", rows-bad, len(exports), bad, kinds)
}
