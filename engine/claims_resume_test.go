package engine_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// A retry forgets the stored answer of each target it asks again, a 5xx and a 429
// as much as a reset, so it is asked and not read back; a target that failed in
// a way a retry cannot fix is not asked and keeps its stored answer and its
// failure.
func TestRetryFailedDropsTheStoredAnswersOfTheTargetsItAsksAgain(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BeginRun("r1", 1, 0); err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{ // URL → the error recorded for it
		"http://a.test/5xx":     "HTTP 503",
		"http://a.test/429":     "HTTP 429 from the target",
		"http://a.test/reset":   "connection reset",
		"http://a.test/refused": "connection refused",
	}
	var resp []store.Response
	for u, msg := range targets {
		if _, err := st.UpsertEntity(types.TypeURL, u, time.Now()); err != nil {
			t.Fatal(err)
		}
		p, _ := json.Marshal(map[string]string{"error": msg, "url": u})
		if _, err := st.AddObservation(store.EntityID(types.TypeURL, u), types.Observation{Collector: "azhaq-http", Kind: "error", Payload: p, ObservedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		resp = append(resp, store.Response{URL: u, Meta: []byte("{}"), Body: []byte("stored")})
	}
	if err := st.SaveResponses(resp); err != nil {
		t.Fatal(err)
	}
	ents, _ := st.Entities()
	obs, _ := st.Observations()
	r, err := engine.RetryFailed(st, ents, obs)
	if err != nil {
		t.Fatal(err)
	}
	if r.Targets != 3 || len(r.Asked) != 3 {
		t.Fatalf("asked again %d targets (%+v), want the 5xx, the 429 and the reset", r.Targets, r.Asked)
	}
	for u, msg := range targets {
		_, kept := st.LoadResponse(u)
		retryable := msg != "connection refused"
		if kept == retryable {
			t.Errorf("%s (%s): stored answer kept = %v", u, msg, kept)
		}
	}
	ents, _ = st.Entities()
	obs, _ = st.Observations()
	if still := engine.FailedTargets(ents, obs); len(still) < 1 {
		t.Errorf("what a retry cannot fix is not in failed any more: %+v", still)
	}
}
