package subcol

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// slowSource holds until its context ends, then gives the names it had.
func slowSource(name string, extra bool, names ...string) source {
	return source{name: name, need: noKey, deflt: true, extra: extra, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		<-ctx.Done()
		return names, ctx.Err()
	}}
}

// A source outside subfinder's default set that is still running when every
// source of that set has answered gets -extra-wait more, then is cut: the run
// is not held to -source-timeout, the others' names are kept, and the cut
// source is listed with the reason.
func TestExtraSourceDoesNotHoldTheRunPastExtraWait(t *testing.T) {
	c := collector(Options{ExtraWait: 200 * time.Millisecond, SourceTimeout: 30 * time.Second},
		fake("core", noKey, true, []string{"www.example.org"}, nil),
		slowSource("extra", true, "late.example.org"),
	)
	t0 := time.Now()
	payload, _ := run(t, c, context.Background())
	if took := time.Since(t0); took > 5*time.Second {
		t.Fatalf("the run took %s: the extra source held it", took)
	}
	row := payload["sources"].(map[string]any)["extra"].(map[string]any)
	if e, _ := row["error"].(string); !strings.Contains(e, "-extra-wait") {
		t.Errorf("the cut source's row does not say why: %v", row)
	}
	if payload["partial"] == true {
		t.Errorf("a cut on purpose is not the run's partial result: %v", payload)
	}
	names, _ := payload["names"].([]any)
	if len(names) != 2 {
		t.Errorf("names %v: the core's and what the extra gave before the cut are kept", names)
	}
}

// An extra that answers inside -extra-wait is not touched, and one named with
// -sources, or with the bound off, runs to -source-timeout.
func TestExtraWaitSparesAnsweringAndNamedSources(t *testing.T) {
	quick := source{name: "quick", need: noKey, deflt: true, extra: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		time.Sleep(100 * time.Millisecond)
		return []string{"q.example.org"}, nil
	}}
	c := collector(Options{ExtraWait: 2 * time.Second}, fake("core", noKey, true, []string{"www.example.org"}, nil), quick)
	payload, _ := run(t, c, context.Background())
	if row := payload["sources"].(map[string]any)["quick"].(map[string]any); row["error"] != nil || row["count"].(float64) != 1 {
		t.Errorf("an extra that answered in time: %v", row)
	}
	for name, o := range map[string]Options{
		"named":     {ExtraWait: 100 * time.Millisecond, SourceTimeout: 600 * time.Millisecond, Only: []string{"core", "slow"}},
		"bound off": {ExtraWait: -1, SourceTimeout: 600 * time.Millisecond},
	} {
		c := collector(o, fake("core", noKey, true, []string{"www.example.org"}, nil), slowSource("slow", true, "x.example.org"))
		t0 := time.Now()
		payload, _ := run(t, c, context.Background())
		if took := time.Since(t0); took < 500*time.Millisecond {
			t.Errorf("%s: the run took %s, the source was cut before -source-timeout", name, took)
		}
		row := payload["sources"].(map[string]any)["slow"].(map[string]any)
		if e, _ := row["error"].(string); strings.Contains(e, "-extra-wait") {
			t.Errorf("%s: %v", name, row)
		}
	}
}
