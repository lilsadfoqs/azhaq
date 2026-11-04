package engine_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

func dirsObs(id, payload string) types.StoredObservation {
	return types.StoredObservation{EntityID: id, Observation: types.Observation{Collector: "azhaq-dirs", Kind: "url", Payload: json.RawMessage(payload)}}
}

// A path the sweep found whose answer was its directory's control's, byte for
// byte, is a catch-all row and folds, whether or not the page fetch of it
// agrees (a 403 is never a catch-all to the fetch); one the sweep did not
// mark stays listed, and so does one a fetch answered differently.
func TestSweepFoldsTheAnswerOfItsDirectorysControl(t *testing.T) {
	ctl := `{"url":"http://h/api/zz1","status":500,"size":22}`
	ents := []types.Entity{
		{ID: "root", Type: types.TypeURL, Key: "http://h/"},
		{ID: "foo", Type: types.TypeURL, Key: "http://h/api/foo"},
		{ID: "bar", Type: types.TypeURL, Key: "http://h/priv/a"},
		{ID: "real", Type: types.TypeURL, Key: "http://h/api/users"},
		{ID: "moved", Type: types.TypeURL, Key: "http://h/api/moved"},
	}
	obs := []types.StoredObservation{
		httpObs("root", `{"status":200,"url":"http://h/"}`),
		// the sweep's rows are stored on the page it swept
		dirsObs("root", `{"url":"http://h/api/foo","via":"dirs","status":500,"catchall":true,"control":`+ctl+`,"control_exact":true}`),
		dirsObs("root", `{"url":"http://h/priv/a","via":"dirs","status":403,"catchall":true,"control":{"url":"http://h/priv/zz2","status":403,"size":9},"control_exact":true}`),
		dirsObs("root", `{"url":"http://h/api/users","via":"dirs","status":200}`),
		dirsObs("root", `{"url":"http://h/api/moved","via":"dirs","status":500,"catchall":true,"control":`+ctl+`,"control_exact":true}`),
		httpObs("foo", `{"status":500,"catchall":true,"control_exact":true,"control":`+ctl+`,"url":"http://h/api/foo"}`),
		httpObs("bar", `{"status":403,"url":"http://h/priv/a"}`),
		httpObs("real", `{"status":200,"url":"http://h/api/users"}`),
		httpObs("moved", `{"status":200,"url":"http://h/api/moved"}`), // the page fetch got another answer than the sweep
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://h/"}}}
	rows := engine.BuildMap(ents, seeds, obs, nil, false)
	f := engine.NewFolder(obs)
	got := map[string]string{}
	for _, r := range rows {
		got[r.Entity.Key] = r.Coverage + "/" + f.Class(r)
	}
	want := map[string]string{
		"http://h/":          "visited/",
		"http://h/api/foo":   "catchall/catchall",
		"http://h/priv/a":    "catchall/catchall",
		"http://h/api/users": "visited/",
		"http://h/api/moved": "visited/",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}
	var folded []engine.MapEntry
	for _, r := range rows {
		if f.Class(r) != "" {
			folded = append(folded, r)
		}
	}
	groups := f.Groups(folded)
	if len(groups) != 1 || groups[0].Count != 2 || len(groups[0].Controls) != 2 {
		t.Fatalf("groups %+v", groups)
	}
	line := groups[0].Line()
	if !strings.Contains(line, "2 URLs of http://h answer as the control does") || !strings.Contains(line, "GET /api/zz1 → 500, 22 bytes") || !strings.Contains(line, "GET /priv/zz2 → 403, 9 bytes") {
		t.Errorf("the line: %s", line)
	}
}

// A fetch that proved a sweep's row to be its directory's catch-all page makes
// it a catch-all row, though the sweep's own row does not say so (a
// directory with a single hit has no control of the sweep's).
func TestAFetchedCatchAllOverridesTheSweepsRow(t *testing.T) {
	ents := []types.Entity{
		{ID: "root", Type: types.TypeURL, Key: "http://h/"},
		{ID: "foo", Type: types.TypeURL, Key: "http://h/api/foo"},
	}
	ctl := `{"url":"http://h/api/zz1","status":500,"size":22}`
	obs := []types.StoredObservation{
		httpObs("root", `{"status":200,"url":"http://h/"}`),
		dirsObs("root", `{"url":"http://h/api/foo","via":"dirs","status":500}`),
		httpObs("foo", `{"status":500,"catchall":true,"control_exact":true,"control":`+ctl+`,"url":"http://h/api/foo"}`),
	}
	seeds := []types.Seed{{Type: types.TypeURL, Keys: map[string]string{"url": "http://h/"}}}
	f := engine.NewFolder(obs)
	for _, r := range engine.BuildMap(ents, seeds, obs, nil, false) {
		if r.Entity.Key == "http://h/api/foo" && (r.Coverage != "catchall" || f.Class(r) != engine.FoldCatchAll) {
			t.Errorf("%+v folds as %q", r, f.Class(r))
		}
	}
}
