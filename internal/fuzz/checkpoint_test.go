package fuzz

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A run reports the inputs it has answered while it goes, and stops
// reporting when it ends: a run that is killed goes on from the last report.
func TestRunReportsAnsweredInputsWhileItGoes(t *testing.T) {
	f := &fake{hook: func(*Request) (*Response, error) {
		time.Sleep(20 * time.Millisecond)
		return &Response{Status: 404, Length: 4, Words: 1, Lines: 1, Header: http.Header{}}, nil
	}}
	var mu sync.Mutex
	var seen []int
	ended := false
	late := false
	st, _ := runFake(t, f, func(c *Config) {
		c.Threads = 1
		c.CheckpointEvery = 30 * time.Millisecond
		c.Checkpoint = func(done Spans, total int) {
			mu.Lock()
			defer mu.Unlock()
			late = late || ended
			n := 0
			for _, s := range done {
				n += s[1] - s[0]
			}
			if total != 6 {
				t.Errorf("total %d, want 6", total)
			}
			seen = append(seen, n)
		}
	})
	mu.Lock()
	ended = true
	got := append([]int(nil), seen...)
	mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if st.Answered != 6 {
		t.Fatalf("answered %d", st.Answered)
	}
	if len(got) < 2 || got[0] >= 6 || got[len(got)-1] <= got[0] {
		t.Errorf("reports of answered inputs: %v", got)
	}
	if late || len(seen) != len(got) {
		t.Errorf("a report came after the run ended: %v", seen)
	}
}

// A write the run this one goes on from sent is held back by the transport:
// no request, no failure, and the input counts as done.
func TestHeldWriteIsNeitherARequestNorAFailure(t *testing.T) {
	f := &fake{hook: func(r *Request) (*Response, error) {
		if r.Input["FUZZ"] == "login" {
			return nil, neterr.ErrNotRepeated
		}
		return &Response{Status: 200, Length: 4, Words: 1, Lines: 1, Header: http.Header{}}, nil
	}}
	st, out := runFake(t, f, nil)
	if st.Requests != 5 || st.Errors != 0 || st.NotRepeated != 1 || len(out) != 5 || st.Done != 6 {
		t.Errorf("requests %d errors %d held %d results %d done %d, want 5 0 1 5 6", st.Requests, st.Errors, st.NotRepeated, len(out), st.Done)
	}
	if len(f.got) != 6 {
		t.Errorf("a held write was tried again: %d sends", len(f.got))
	}
}
