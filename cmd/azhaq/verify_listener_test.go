package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/proof"
	"github.com/lilsadfoqs/azhaq/internal/verify"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

func namedRedisObs(port int, hosts ...string) []types.StoredObservation {
	var obs []types.StoredObservation
	for _, h := range hosts {
		raw, _ := json.Marshal(map[string]any{
			"host": h, "ip": "127.0.0.1",
			"services": []map[string]any{{"port": port, "service": "redis", "product": "Redis", "version": "7.2.0"}},
		})
		obs = append(obs, types.StoredObservation{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: raw}})
	}
	return obs
}

// One Redis listener reached by its address and two names is one INFO read and
// one finding, which lists the names; tiers and the headline count it once (#587).
func TestVerifyOneReadAndOneFindingForAListenerReachedByNames(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newRedisFixture(t, redisInfoResp())
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	obs := namedRedisObs(fx.port, "127.0.0.1", "redis.example.com", "www.example.com")
	results, failures, note := verifyStage(context.Background(), st, obs, nil, "azhaq run -verify")
	if len(failures) > 0 || len(results) != 1 {
		t.Fatalf("results %d failures %v, want one result", len(results), failures)
	}
	if n := fx.infoCount(); n != 1 {
		t.Errorf("%d INFO reads, want 1", n)
	}
	if r := results[0]; r.Host != "redis.example.com" || !slices.Equal(r.Names, []string{"127.0.0.1", "redis.example.com", "www.example.com"}) {
		t.Errorf("result host %s names %v", r.Host, r.Names)
	}
	if want := "1 results (1 proved"; !strings.Contains(note, want) {
		t.Errorf("note %q, want %q", note, want)
	}
	stored, _ := st.Observations()
	set, _, _ := listenerRecords(stored, "azhaq run -verify")
	if len(set.Findings) != 1 {
		t.Fatalf("%d findings, want 1: %+v", len(set.Findings), set.Findings)
	}
	if c := set.counts(); c.Findings != 1 {
		t.Errorf("tier counts %+v", c)
	}
	pairs := listenerPairs(set)
	if len(pairs) != 1 || !slices.Equal(pairs[0].l.Also, []string{"127.0.0.1", "www.example.com"}) {
		t.Errorf("listener rows %+v, want one naming the other hosts", pairs)
	}
}

// A workspace that stored one result for each name (before a read stood for
// every name) reads as one finding, with the names; a name whose answer
// differs stays its own.
func TestFindingsFoldVerifyResultsOfOneListener(t *testing.T) {
	row := func(host, excerpt string) types.StoredObservation {
		r := verify.Result{Kind: verify.KindUnauthenticatedRead, Label: verify.Proved, Severity: "info", Host: host, Port: 6379,
			Target: host + ":6379", Product: "Redis", Version: "5.0.7", Request: "INFO server", Evidence: excerpt,
			Proof: &proof.Proof{ObservedAt: "2026-11-17T03:00:00Z", Method: "INFO server", Target: host + ":6379", Excerpt: excerpt,
				ExcerptPart: "response", How: "azhaq-verify", Reproduce: "nc " + host + " 6379"}}
		raw, _ := json.Marshal(r)
		return types.StoredObservation{Observation: types.Observation{Collector: "azhaq-verify", Kind: "verify", Payload: raw}}
	}
	ports, _ := json.Marshal(map[string]any{"host": "redis.example.com", "ip": "127.77.0.9", "services": []map[string]any{{"port": 6379, "service": "redis"}}})
	obs := []types.StoredObservation{
		{Observation: types.Observation{Collector: "azhaq-ports", Kind: "ports", Payload: ports}},
		row("127.77.0.9", "redis_version:5.0.7"), row("redis.example.com", "redis_version:5.0.7"), row("www.example.com", "redis_version:5.0.7"),
		row("other.example.com", "redis_version:5.0.7 other"),
	}
	addrs := map[string]string{"redis.example.com": "127.77.0.9", "www.example.com": "127.77.0.9", "other.example.com": "127.77.0.9"}
	got := foldVerifyResults(verifyResultsOf(obs), addrs)
	if len(got) != 2 {
		t.Fatalf("%d results, want 2 (the folded one, and the name whose answer differs): %+v", len(got), got)
	}
	if r := got[0]; r.Host != "redis.example.com" || !slices.Equal(r.Names, []string{"127.77.0.9", "redis.example.com", "www.example.com"}) {
		t.Errorf("folded result %s %v", r.Host, r.Names)
	}
}
