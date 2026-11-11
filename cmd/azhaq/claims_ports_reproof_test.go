package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
	"github.com/lilsadfoqs/azhaq/internal/ledger"
	"github.com/lilsadfoqs/azhaq/store"
)

// A -verify read is two ledger lines of the collector azhaq-verify: the tcp
// line of its connection and, after it, a probe line of the read.
func TestVerifyReadIsATCPLineAndAProbeLineOfAzhaqVerify(t *testing.T) {
	egress.Reset()
	t.Cleanup(egress.Reset)
	fx := newRedisFixture(t, redisInfoResp())
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ledPath := filepath.Join(dir, "ledger.jsonl")
	led, err := ledger.Open(ledPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Use(led)
	defer ledger.Use(nil)
	results, failures, _ := verifyStage(context.Background(), st, redisObs(fx.port, ""), nil, "azhaq run -verify")
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 || len(results) != 1 {
		t.Fatalf("results %v failures %v", results, failures)
	}
	var seq []string
	var tcpAt, probeAt int64
	_ = ledger.Read(ledPath, func(e ledger.Entry) error {
		if e.Collector != "azhaq-verify" {
			return nil
		}
		seq = append(seq, e.Kind)
		switch e.Kind {
		case "tcp":
			tcpAt = e.Seq
		case ledger.KindProbe:
			probeAt = e.Seq
			if e.Proto != "redis" {
				t.Errorf("the probe line names protocol %q: %+v", e.Proto, e)
			}
		}
		return nil
	})
	if strings.Join(seq, ",") != "tcp,probe" || probeAt <= tcpAt {
		t.Errorf("the lines of azhaq-verify are %v (tcp at %d, probe at %d), want the tcp line and then one probe line", seq, tcpAt, probeAt)
	}
}

// A -verify read is held to the scope, the kill file, -max-requests and the
// pace: outside the scope, with the kill file there or the budget spent
// nothing is sent and a note says so, and under a pace the reads are spaced.
func TestVerifyReadsGoThroughScopeKillFileBudgetAndPace(t *testing.T) {
	setup := func(t *testing.T) (*redisFixture, *store.Store) {
		t.Helper()
		egress.Reset()
		t.Cleanup(egress.Reset)
		st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return newRedisFixture(t, redisInfoResp()), st
	}
	t.Run("scope", func(t *testing.T) {
		fx, st := setup(t)
		egress.SetScope(func(host string) bool { return host == "192.0.2.99" })
		results, failures, note := verifyStage(context.Background(), st, redisObs(fx.port, ""), nil, "azhaq run -verify")
		if len(results) != 0 || len(failures) != 0 || len(fx.requests()) != 0 || !strings.Contains(note, "1 verification reads were not sent: their targets are outside the scope") {
			t.Errorf("results %v, failures %v, %d requests, note %q", results, failures, len(fx.requests()), note)
		}
	})
	t.Run("kill file", func(t *testing.T) {
		fx, st := setup(t)
		k := filepath.Join(t.TempDir(), "k.stop")
		if err := os.WriteFile(k, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(egress.SetKill(k))
		results, failures, note := verifyStage(context.Background(), st, redisObs(fx.port, ""), nil, "azhaq run -verify")
		if len(results) != 0 || len(failures) != 0 || len(fx.requests()) != 0 || !strings.Contains(note, "1 verification reads were not sent: the run's limit stopped them") {
			t.Errorf("results %v, failures %v, %d requests, note %q", results, failures, len(fx.requests()), note)
		}
	})
	t.Run("budget", func(t *testing.T) {
		fx, st := setup(t)
		egress.SetMaxRequests(1)
		_ = egress.Take()
		results, _, note := verifyStage(context.Background(), st, redisObs(fx.port, ""), nil, "azhaq run -verify")
		if len(results) != 0 || len(fx.requests()) != 0 || !strings.Contains(note, "the run's limit stopped them") {
			t.Errorf("results %v, %d requests, note %q", results, len(fx.requests()), note)
		}
	})
	t.Run("pace", func(t *testing.T) {
		fx, st := setup(t)
		other, third := newRedisFixture(t, redisInfoResp()), newRedisFixture(t, redisInfoResp())
		obs := append(append(redisObs(fx.port, ""), redisObs(other.port, "")...), redisObs(third.port, "")...)
		egress.SetRate(4) // a burst of one: the next two wait 250 ms each
		t0 := time.Now()
		results, _, _ := verifyStage(context.Background(), st, obs, nil, "azhaq run -verify")
		if took := time.Since(t0); len(results) != 3 || took < 450*time.Millisecond {
			t.Errorf("%d results in %s at 4 a second: the reads are not paced", len(results), took)
		}
	})
}

// -p top-100 asks the top 100 alone, -p default,12346 adds a port to the
// first pass of the default scan (1040 ports), and the plan counts what is asked.
func TestPortsTopHundredAsksTheTopHundredAndDefaultPlusAPortAsksOneMore(t *testing.T) {
	count := func(spec string) float64 {
		t.Helper()
		return stageAmount(planCost(t, "-cidr", "127.0.0.0/30", "-ports", spec, "-allow", "127.0.0.0/30", "-sources", "none")["ports"], "estimate", "connects")
	}
	if got := count("top-100"); got != 4*100 {
		t.Errorf("-p top-100: the plan counts %v connects, want 400", got)
	}
	if got := count("default"); got != 4*1040 {
		t.Errorf("-p default: the plan counts %v connects, want 4160 (1040 ports on each of 4 addresses)", got)
	}
	if got := count("default,12346"); got != 4*1041 {
		t.Errorf("-p default,12346: the plan counts %v connects, want 4164", got)
	}
}
