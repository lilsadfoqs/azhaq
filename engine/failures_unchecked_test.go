package engine_test

import (
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/types"
)

// A source that left names unchecked is a failure until a later run asks
// those names: after a resume answered every one, nothing is left failed.
func TestSourceRowAboutUncheckedNamesClearsWhenResumeAsksThem(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	ents := []types.Entity{
		{ID: "d", Type: types.TypeDomain, Key: "example.org"},
		{ID: "a", Type: types.TypeHostname, Key: "a.example.org"},
		{ID: "b", Type: types.TypeHostname, Key: "b.example.org"},
	}
	obs := func(entity, collector, kind, payload string, at time.Time) types.StoredObservation {
		return types.StoredObservation{EntityID: entity, Observation: types.Observation{Collector: collector, Kind: kind, Payload: []byte(payload), ObservedAt: at}}
	}
	listed := obs("d", "azhaq-subdomains", "subdomains",
		`{"domain":"example.org","unverified":["a.example.org","b.example.org"],"sources":{"history":{"error":"2 of its names not checked: cut short; azhaq resume checks them","not_checked":2}}}`, t0)
	failures := func(o ...types.StoredObservation) int {
		n := 0
		for _, f := range engine.Failures(ents, o) {
			if f.Collector == "azhaq-subdomains" {
				n += f.Count
			}
		}
		return n
	}
	if n := failures(listed); n != 1 {
		t.Fatalf("before the resume: %d failures, want 1", n)
	}
	answer := func(entity, payload string) types.StoredObservation {
		return obs(entity, "azhaq-dns", "dns", payload, t0.Add(time.Minute))
	}
	if n := failures(listed, answer("a", `{"result":"nxdomain"}`), answer("b", `{"result":"ok","ips":["127.0.0.1"]}`)); n != 0 {
		t.Errorf("after the resume asked both names: %d failures, want 0", n)
	}
	// A resolver that failed again is no answer: the names are still unchecked.
	if n := failures(listed, answer("a", `{"result":"nxdomain"}`), answer("b", `{"error":"timeout","degraded":true}`)); n != 1 {
		t.Errorf("one name still unchecked: %d failures, want 1", n)
	}
}
