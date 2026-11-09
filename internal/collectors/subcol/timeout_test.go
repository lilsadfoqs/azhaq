package subcol

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// A -source-timeout under a second bounds every source to the millisecond,
// the one that asks again and again (subdomain.center) as the others: the
// session holds whole seconds, which made it 30 s.
func TestSourceTimeoutUnderASecondHoldsForEverySource(t *testing.T) {
	hold := func(name string) source {
		return source{name: name, need: noKey, deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			return nil, ctx.Err()
		}}
	}
	for name, s := range map[string]source{"plain": hold("slow"), "sampled": sampled(hold("slow"))} {
		c := collector(Options{SourceTimeout: 300 * time.Millisecond, NoHistory: true}, s)
		t0 := time.Now()
		payload, _ := run(t, c, context.Background())
		took := time.Since(t0)
		if took < 250*time.Millisecond || took > 1500*time.Millisecond {
			t.Errorf("%s: the run took %s with -source-timeout 300ms", name, took)
		}
		row, _ := payload["sources"].(map[string]any)["slow"].(map[string]any)
		if e, _ := row["error"].(string); !strings.Contains(e, "300ms") && !strings.Contains(e, "deadline") {
			t.Errorf("%s: the row does not show the bound: %v", name, row)
		}
	}
}

// The wait is read from the run, not rounded down to whole seconds.
func TestSourceTimeoutOfRun(t *testing.T) {
	if d := sourceTimeoutOf(context.WithValue(context.Background(), timeoutKey{}, 750*time.Millisecond)); d != 750*time.Millisecond {
		t.Errorf("a run's 750ms is %s", d)
	}
	if d := sourceTimeoutOf(context.Background()); d != DefaultSourceTimeout {
		t.Errorf("no bound given is %s", d)
	}
}

func TestRoundBudget(t *testing.T) {
	for in, want := range map[time.Duration]string{499600 * time.Microsecond: "500ms", 14 * time.Second: "14s", 14400 * time.Millisecond: "14s"} {
		if got := roundBudget(in).String(); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// The session's whole seconds, which sources such as crt.sh's database read as
// a connect and statement limit, round up: a bound under a second is never 0,
// which they read as no limit.
func TestSessionTimeoutIsNeverZero(t *testing.T) {
	for in, want := range map[time.Duration]int{300 * time.Millisecond: 1, time.Second: 1, 1500 * time.Millisecond: 2, 30 * time.Second: 30} {
		var got int
		probe := source{name: "probe", need: noKey, deflt: true, collect: func(_ context.Context, _ string, _ []string, sess *subscraping.Session) ([]string, error) {
			got = sess.Timeout
			return nil, nil
		}}
		run(t, collector(Options{SourceTimeout: in, NoHistory: true}, probe), context.Background())
		if got != want {
			t.Errorf("-source-timeout %s: the session holds %d s, want %d", in, got, want)
		}
	}
}
