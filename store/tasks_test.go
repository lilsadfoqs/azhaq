package store

import (
	"path/filepath"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func TestProgressReadsTheRunsState(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if p, err := st.Progress(); err != nil || p != (Progress{}) {
		t.Fatalf("no runs: %+v %v", p, err)
	}
	if err := st.BeginRun("r1", 4, 0); err != nil {
		t.Fatal(err)
	}
	seed := types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://a.test/"}}
	_ = st.SaveTasks([]Task{{ID: "t1", Collector: "c", Seed: seed}, {ID: "t2", Collector: "c", Seed: seed}}, []string{"t1"}, nil)
	_ = st.AddRunRequests(4)
	_ = st.AddRunRequests(3) // a resume of the same run adds
	p, err := st.Progress()
	if err != nil || p.RunID != "r1" || p.Left != 1 || !p.Resumable || p.Requests != 7 {
		t.Fatalf("%+v %v", p, err)
	}
	_ = st.SaveTasks(nil, []string{"t2"}, nil)
	if p, _ := st.Progress(); p.Resumable || p.Left != 0 || p.Requests != 7 {
		t.Errorf("done: %+v", p)
	}
}
