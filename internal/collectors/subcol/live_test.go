package subcol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"

	"github.com/lilsadfoqs/azhaq/types"
)

// The rows of the sources are readable after a stop that lost the run's
// summary (the engine drops what a task emitted when it is stopped under a
// budget, or by the kill file): each source asked is there with its names, a
// source that answered has no error, and one the stop caught asking is marked
// running, not failed.
func TestLiveRowsSurviveALostSummary(t *testing.T) {
	ForgetLive()
	fast := source{name: "fast", need: noKey, deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		countCall(ctx)
		return []string{"a.example.org"}, nil
	}}
	slow := source{name: "slow", need: noKey, deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		countCall(ctx)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	c := collector(Options{NoHistory: true}, fast, slow)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	lost := errors.New("the engine took nothing: the run had stopped")
	_, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(types.Observation) error { return lost })
	if err == nil {
		t.Fatal("the summary row was refused: Run says so")
	}
	rows, ok := Live("example.org")
	if !ok {
		t.Fatal("no rows for the domain")
	}
	f, _ := rows["fast"].(map[string]any)
	s, _ := rows["slow"].(map[string]any)
	if f == nil || f["error"] != nil || f["running"] != nil || f["count"] != 1 {
		t.Errorf("fast: %v", f)
	}
	if s == nil || s["error"] == nil || s["running"] != true {
		t.Errorf("slow was asking when the run stopped: %v", s)
	}
	if _, ok := Live("other.example.org"); ok {
		t.Error("rows of a domain that was not run")
	}
	ForgetLive()
	if _, ok := Live("example.org"); ok {
		t.Error("ForgetLive keeps rows")
	}
}
