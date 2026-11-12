package subcol

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"

	"github.com/lilsadfoqs/azhaq/catalog"
	"github.com/lilsadfoqs/azhaq/internal/limit"
	"github.com/lilsadfoqs/azhaq/types"
)

func fake(name string, need keyNeed, deflt bool, names []string, err error) source {
	return source{name: name, need: need, deflt: deflt, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		return names, err
	}}
}

func collector(o Options, srcs ...source) *Collector {
	c := New(o)
	c.sources = srcs
	c.limiter = limit.New(0, 1)
	return c
}

func run(t *testing.T, c *Collector, ctx context.Context) (map[string]any, types.RunMeta) {
	t.Helper()
	var payload map[string]any
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload, meta
}

func TestPlanKeysAndSelection(t *testing.T) {
	srcs := []source{
		fake("free", noKey, true, nil, nil),
		fake("slow", noKey, false, nil, nil),
		fake("paid", requiredKey, true, nil, nil),
		fake("better-with-key", optionalKey, true, nil, nil),
	}
	names := func(c *Collector) (string, map[string]string) {
		run, skipped := c.plan()
		var out []string
		for _, s := range run {
			out = append(out, s.name)
		}
		return strings.Join(out, ","), skipped
	}
	got, skipped := names(collector(Options{}, srcs...))
	if got != "free,better-with-key" || skipped["paid"] != "needs a key" {
		t.Errorf("default: %s %v", got, skipped)
	}
	if got, _ = names(collector(Options{All: true, Keys: map[string][]string{"paid": {"k"}}}, srcs...)); got != "free,slow,paid,better-with-key" {
		t.Errorf("all with key: %s", got)
	}
	if got, _ = names(collector(Options{Only: []string{"slow"}}, srcs...)); got != "slow" {
		t.Errorf("only: %s", got)
	}
	if got, _ = names(collector(Options{Exclude: []string{"FREE"}}, srcs...)); got != "better-with-key" {
		t.Errorf("exclude: %s", got)
	}
}

func TestMergeAndEarlyHints(t *testing.T) {
	c := collector(Options{},
		fake("a", noKey, true, []string{"www.example.org", "*.api.example.org", "evil.test", "example.org"}, nil),
		fake("b", noKey, true, []string{"WWW.example.org.", "mail.example.org"}, errors.New("partial page")),
		fake("c", noKey, true, nil, errors.New("down")),
	)
	var mu sync.Mutex
	var early []string
	ctx := catalog.WithHints(context.Background(), func(seeds []types.Seed) {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range seeds {
			early = append(early, s.Keys["fqdn"])
		}
	})
	payload, meta := run(t, c, ctx)
	sort.Strings(early)
	if strings.Join(early, ",") != "api.example.org,example.org,mail.example.org,www.example.org" {
		t.Errorf("early hints %v", early)
	}
	if len(meta.NextHints) != 0 {
		t.Errorf("names hinted early came back again: %v", meta.NextHints)
	}
	if payload["count"].(float64) != 4 || payload["degraded"] != nil {
		t.Errorf("payload %v", payload)
	}
	srcs := payload["sources"].(map[string]any)
	if srcs["c"].(map[string]any)["error"] != "down" || srcs["b"].(map[string]any)["count"].(float64) != 2 {
		t.Errorf("per-source %v", srcs)
	}
	if !strings.Contains(payload["warning"].(string), "b, c") {
		t.Errorf("warning %v", payload["warning"])
	}
}

func TestNothingFoundAndBrokenIsDegraded(t *testing.T) {
	c := collector(Options{}, fake("a", noKey, true, nil, errors.New("429")))
	payload, meta := run(t, c, context.Background())
	if payload["degraded"] != true || meta.Status != types.StatusDegraded {
		t.Fatalf("payload %v meta %+v", payload, meta)
	}
	if c2 := collector(Options{}, fake("a", noKey, true, nil, nil)); true {
		payload, _ = run(t, c2, context.Background())
		if payload["degraded"] != nil {
			t.Fatalf("an answered zero is not degraded: %v", payload)
		}
	}
}

func TestLoadProviders(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "providers.yaml")
	if err := os.WriteFile(p, []byte("securitytrails: [k1, ' k2 ']\nCensys:\n  - id:secret\nvirustotal: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, used, err := LoadProviders(filepath.Join(dir, "missing.yaml"), p)
	if err != nil || used != p {
		t.Fatal(used, err)
	}
	if strings.Join(keys["securitytrails"], ",") != "k1,k2" || keys["censys"][0] != "id:secret" {
		t.Errorf("keys %v", keys)
	}
	if _, ok := keys["virustotal"]; ok {
		t.Errorf("empty list kept")
	}
	if k, used, err := LoadProviders(filepath.Join(dir, "none.yaml")); err != nil || used != "" || len(k) != 0 {
		t.Errorf("missing file: %v %q %v", k, used, err)
	}
}

func TestDerivedDomainWaitsLess(t *testing.T) {
	defer func(d time.Duration) { fanoutTimeout = d }(fanoutTimeout)
	fanoutTimeout = 50 * time.Millisecond
	slow := source{name: "slow", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	c := collector(Options{SourceTimeout: time.Minute}, slow)
	t0 := time.Now()
	var payload map[string]any
	_, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org", types.DerivedKey: "1"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil || time.Since(t0) > 5*time.Second {
		t.Fatalf("derived domain took %s (%v)", time.Since(t0), err)
	}
	if payload["degraded"] != true {
		t.Errorf("a source cut short must be reported: %v", payload)
	}
}

// hang is a source that never answers until its context ends (crt.sh on a
// bad day), or at all when it ignores the context (release closes it).
func hang(name string, release <-chan struct{}) source {
	return source{name: name, deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		if release != nil {
			<-release
			return nil, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
}

func TestRunDeadlineKeepsWhatSourcesGave(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	c := collector(Options{SourceTimeout: time.Minute},
		fake("fast", noKey, true, []string{"www.example.org", "api.example.org"}, nil),
		fake("other", noKey, true, []string{"mail.example.org"}, nil),
		hang("slow", nil),
		hang("deaf", stuck),
	)
	// A quarter of what is left is kept to emit: 2 s leaves 0.5 s, room enough
	// on a busy runner under -race (0.4 s left 0.1 s, and missed it once).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	t0 := time.Now()
	var payload map[string]any
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err() // as the engine does: nothing is taken after the run ends
		}
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil || ctx.Err() != nil {
		t.Fatalf("not emitted before the run's deadline (%s): %v", time.Since(t0), err)
	}
	if meta.Status != types.StatusDegraded || payload["degraded"] != true || payload["partial"] != true {
		t.Errorf("a result cut short by -timeout is partial: %+v %v", meta, payload)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "api.example.org,mail.example.org,www.example.org" {
		t.Errorf("names the sources gave were thrown away: %q", got)
	}
	srcs := payload["sources"].(map[string]any)
	for _, name := range []string{"slow", "deaf"} {
		msg, _ := srcs[name].(map[string]any)["error"].(string)
		if !strings.Contains(msg, "-timeout") {
			t.Errorf("%s: %q should say the run cut it short", name, msg)
		}
	}
	if srcs["fast"].(map[string]any)["error"] != nil || srcs["fast"].(map[string]any)["count"].(float64) != 2 {
		t.Errorf("fast: %v", srcs["fast"])
	}
	if len(meta.NextHints) != 3 {
		t.Errorf("hints %v", meta.NextHints)
	}
}

func TestSourceTimeoutAbandonsOneSourceOnly(t *testing.T) {
	stuck := make(chan struct{})
	defer close(stuck)
	c := collector(Options{SourceTimeout: 50 * time.Millisecond},
		fake("fast", noKey, true, []string{"www.example.org"}, nil),
		hang("slow", nil),
		hang("deaf", stuck),
	)
	t0 := time.Now()
	payload, meta := run(t, c, context.Background())
	if time.Since(t0) > 5*time.Second {
		t.Fatalf("waited %s on a source past -source-timeout", time.Since(t0))
	}
	if meta.Status != types.StatusOK || payload["degraded"] != nil || payload["partial"] != nil {
		t.Errorf("one slow source among answers is a warning, not a partial result: %+v %v", meta, payload)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "www.example.org" {
		t.Errorf("names %q", got)
	}
	srcs := payload["sources"].(map[string]any)
	for _, name := range []string{"slow", "deaf"} {
		msg, _ := srcs[name].(map[string]any)["error"].(string)
		if !strings.Contains(msg, "50ms (-source-timeout)") {
			t.Errorf("%s: %q should name -source-timeout", name, msg)
		}
	}
	if payload["warning"] != "failed: deaf, slow" {
		t.Errorf("warning %v", payload["warning"])
	}
}

func TestCancelledRunStillEmitsWhatItHas(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// A source's names are hinted once its answer is recorded: the signal
	// that fast is in before slow pulls the plug.
	answered := make(chan struct{})
	var once sync.Once
	ctx = catalog.WithHints(ctx, func([]types.Seed) { once.Do(func() { close(answered) }) })
	c := collector(Options{SourceTimeout: time.Minute},
		fake("fast", noKey, true, []string{"www.example.org"}, nil),
		source{name: "slow", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
			<-answered
			cancel() // Ctrl-C while it is still working
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	)
	payload, meta := run(t, c, ctx)
	if meta.Status != types.StatusDegraded || payload["degraded"] != true || payload["count"].(float64) != 1 {
		t.Errorf("%+v %v", meta, payload)
	}
	msg, _ := payload["sources"].(map[string]any)["slow"].(map[string]any)["error"].(string)
	if !strings.Contains(msg, "stopped with the run") {
		t.Errorf("slow: %q", msg)
	}
	// An emit the run's end refuses (the engine's) makes the task cancelled.
	meta, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(types.Observation) error { return ctx.Err() })
	if meta.Status != types.StatusCancelled || !errors.Is(err, context.Canceled) {
		t.Errorf("%+v %v", meta, err)
	}
}

func strs(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.(string))
	}
	return out
}

// A padding source's names need a DNS check (Options.Verify). Under a tight
// -timeout that check cannot finish, and running it anyway would blow the
// deadline so the engine stores nothing — the v0.8 "0 names on -timeout"
// bug. The collector must emit the real names and drop the unchecked
// padding name instead.
func TestRunDeadlineSkipsSlowPaddingVerify(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"junk.example.org"}, nil)
	pad.verify = true
	stuck := make(chan struct{})
	defer close(stuck)
	c := collector(Options{SourceTimeout: time.Minute, Verify: func(ctx context.Context, _ string, names []string) ([]string, []string) {
		<-ctx.Done() // the DNS check never answers in time
		return nil, names
	}},
		fake("fast", noKey, true, []string{"www.example.org"}, nil),
		pad,
		hang("deaf", stuck), // keeps a source running so the -timeout cuts the wait
	)
	// 2 s, of which a quarter (500 ms) is the time to emit: at 300 ms the 75 ms
	// left were too short on a busy runner.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	t0 := time.Now()
	var payload map[string]any
	_, err := c.Run(ctx, types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		if ctx.Err() != nil {
			return ctx.Err() // as the engine does: nothing is taken after the run ends
		}
		return json.Unmarshal(o.Payload, &payload)
	})
	if err != nil || ctx.Err() != nil {
		t.Fatalf("emitted nothing before the deadline (%s): %v", time.Since(t0), err)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "junk.example.org,www.example.org" || strings.Join(strs(payload["unverified"]), ",") != "junk.example.org" {
		t.Errorf("want the real name kept and the unchecked padding name listed unverified, got %q", got)
	}
	if payload["partial"] != true {
		t.Errorf("a cut-short result is partial: %+v", payload)
	}
	if msg, _ := payload["sources"].(map[string]any)["pad"].(map[string]any)["error"].(string); !strings.Contains(msg, "not checked") {
		t.Errorf("padding source should say its names were not checked: %q", msg)
	}
}

// allLive is a Verify that finds every name live.
func allLive(_ context.Context, _ string, names []string) ([]string, []string) { return names, nil }

func TestSampledGathersUntilSaturated(t *testing.T) {
	answers := []struct {
		names []string
		err   error
	}{
		{[]string{"a.example.org", "b.example.org", "c.example.org", "d.example.org"}, nil},
		{[]string{"c.example.org", "d.example.org", "e.example.org", "f.example.org"}, nil},
		{[]string{"a.example.org", "b.example.org", "c.example.org", "d.example.org", "e.example.org", "f.example.org"}, nil}, // nothing new: stop
		{[]string{"never"}, nil},
	}
	calls := 0
	s := sampled(source{name: "s", collect: func(_ context.Context, _ string, keys []string, _ *subscraping.Session) ([]string, error) {
		if len(keys) > 0 {
			return []string{"keyed"}, nil
		}
		a := answers[calls]
		calls++
		return a.names, a.err
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	chk := newChecker(ctx, "example.org", allLive, nil)
	ctx = context.WithValue(ctx, checkerKey{}, chk)
	got, err := s.collect(ctx, "example.org", nil, nil)
	if err != nil || calls != 3 || strings.Join(got, ",") != "a.example.org,b.example.org,c.example.org,d.example.org,e.example.org,f.example.org" {
		t.Fatalf("got %v %v after %d calls", got, err, calls)
	}
	if got, _ := s.collect(ctx, "example.org", []string{"k"}, nil); len(got) != 1 || got[0] != "keyed" {
		t.Fatalf("a key should page once: %v", got)
	}
	// A failed first call is the source's failure; a later one ends the
	// asking and keeps what the rounds gave.
	fail := errors.New("unexpected status code 500 received from x")
	calls = 0
	bad := sampled(source{name: "b.example.org", collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		calls++
		if calls == 1 {
			return []string{"a.example.org"}, nil
		}
		return nil, fail
	}})
	if got, err := bad.collect(ctx, "example.org", nil, nil); err != nil || len(got) != 1 {
		t.Fatalf("a later round refused: %v %v", got, err)
	}
	first := sampled(source{name: "f.example.org", collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		return nil, fail
	}})
	if _, err := first.collect(ctx, "example.org", nil, nil); err == nil {
		t.Fatal("first-round error swallowed")
	}
}

// subdomain.center answers a random sample per call. With resolvers, a
// round's new names are resolved before the next round is asked and a name
// is resolved once. A round that adds no name that resolves ends the asking
// only when the names seen are most of the pool the rounds' repeats
// estimate: a live name may be among the ones not yet seen.
func TestSampledStopsWhenNothingNewResolvesAndThePoolIsCovered(t *testing.T) {
	name := func(i int) string { return "g" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".example.org" }
	span := func(from, to int) []string {
		var out []string
		for i := from; i < to; i++ {
			out = append(out, name(i))
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		rounds [][]string
		live   []string
		calls  int // samples checked (one that gave nothing new is not)
		stop   string
		found  int
	}{
		// 100 names; the live one is in the third sample only: two samples
		// with no live name do not end the asking while a quarter of the
		// pool is unseen.
		{"a pool not yet covered is asked again", [][]string{span(0, 50), span(25, 75), span(50, 100), span(0, 100)}, []string{name(90)}, 3, stopSaturated, 1},
		// The second sample repeats 99 names of the first and adds one: the
		// pool is estimated at 101 and all of it seen, and nothing live ends
		// the asking.
		{"a covered pool with nothing live ends it", [][]string{span(0, 100), span(1, 101), span(2, 102)}, nil, 2, stopNoLive, 0},
	} {
		asked := 0
		pad := sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
			r := tc.rounds[min(asked, len(tc.rounds)-1)]
			asked++
			return r, nil
		}}))
		live := map[string]bool{}
		for _, n := range tc.live {
			live[n] = true
		}
		sent := map[string]int{}
		c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
			var out []string
			for _, n := range names {
				sent[n]++
				if live[n] {
					out = append(out, n)
				}
			}
			return out, nil
		}}, pad)
		payload, _ := run(t, c, context.Background())
		row := payload["sources"].(map[string]any)["pad"].(map[string]any)
		if got := len(row["rounds"].([]any)); got != tc.calls {
			t.Errorf("%s: %d samples checked, want %d (%v)", tc.name, got, tc.calls, row)
		}
		if got, _ := row["sampling_stopped"].(string); got != tc.stop {
			t.Errorf("%s: stopped %q, want %q", tc.name, got, tc.stop)
		}
		if got := len(strs(payload["names"])); got != tc.found {
			t.Errorf("%s: %d names kept, want %d", tc.name, got, tc.found)
		}
		for n, k := range sent {
			if k != 1 {
				t.Errorf("%s: %s resolved %d times", tc.name, n, k)
			}
		}
	}
}

// Without -live nothing is resolved: the guesses are listed, unverified,
// and not kept in the history.
func TestNoCheckListsGuessesUnverified(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	pad := fake("pad", noKey, true, []string{"junk.example.org", "real.example.org"}, nil)
	pad.verify = true
	asked := 0
	c := collector(Options{NoCheck: true, Verify: func(context.Context, string, []string) ([]string, []string) {
		asked++
		return nil, nil
	}}, pad, fake("a", noKey, true, []string{"www.example.org"}, nil))
	payload, _ := run(t, c, context.Background())
	if asked != 0 {
		t.Errorf("%d DNS checks without -live", asked)
	}
	if got := strings.Join(strs(payload["names"]), ","); got != "junk.example.org,real.example.org,www.example.org" {
		t.Errorf("names %s", got)
	}
	if got := strings.Join(strs(payload["unverified"]), ","); got != "junk.example.org,real.example.org" {
		t.Errorf("unverified %s", got)
	}
	if m, _ := loadHistory(historyPath(os.Getenv("AZHAQ_DATA_DIR"), "example.org")); len(m) != 1 || m["www.example.org"].Last == "" {
		t.Errorf("history holds %v", m)
	}
}

// The resolvers failing on a name leaves it listed, unverified, not dropped.
func TestFailedCheckIsUnverifiedNotDropped(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"flaky.example.org", "dead.example.org", "real.example.org"}, nil)
	pad.verify = true
	c := collector(Options{NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
		var live, failed []string
		for _, n := range names {
			switch n {
			case "real.example.org":
				live = append(live, n)
			case "flaky.example.org":
				failed = append(failed, n)
			}
		}
		return live, failed
	}}, pad)
	payload, _ := run(t, c, context.Background())
	if got := strings.Join(strs(payload["names"]), ","); got != "flaky.example.org,real.example.org" {
		t.Errorf("names %s", got)
	}
	if got := strings.Join(strs(payload["unverified"]), ","); got != "flaky.example.org" || payload["dropped"] != float64(1) {
		t.Errorf("unverified %s dropped %v", got, payload["dropped"])
	}
	if e, _ := payload["sources"].(map[string]any)["pad"].(map[string]any)["error"].(string); !strings.Contains(e, "1 of its names not checked") {
		t.Errorf("row error %q", e)
	}
}

func TestSampledRowCountsCalls(t *testing.T) {
	answers := [][]string{{"a.example.org", "b.example.org"}, {"c.example.org", "d.example.org"}, {"a.example.org", "c.example.org"}}
	var mu sync.Mutex
	i := 0
	s := sampled(source{name: "s", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		a := answers[min(i, len(answers)-1)]
		i++
		return a, nil
	}})
	c := collector(Options{SourceTimeout: 5 * time.Second, Verify: allLive}, s)
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["s"].(map[string]any)
	if row["calls"] != float64(3) || row["count"] != float64(4) {
		t.Fatalf("row %v", row)
	}
}

// The first sample of guesses is always checked in full, at any speed: it is
// what subfinder | dnsx checks. Another is taken only while the last had a
// new name that resolves and it fits what is left of the budget, measured by
// what the last one cost; -guess-samples takes up to N with no budget. The
// row says why it stopped.
func TestSampledFirstSampleThenWithinTheBudget(t *testing.T) {
	old := sampleBudget
	defer func() { sampleBudget = old }()
	for _, tc := range []struct {
		name     string
		perName  time.Duration // what a lookup takes
		budget   time.Duration
		samples  int // -guess-samples
		min, max int // samples taken
		stopped  string
	}{
		{"a sample costs more than the budget", time.Millisecond, 50 * time.Millisecond, 0, 1, 1, stopBudget},
		{"samples fit the budget a while", time.Millisecond, 350 * time.Millisecond, 0, 3, 5, stopBudget},
		{"fast lookups reach the ceiling", 0, time.Minute, 0, sampleRounds, sampleRounds, stopRounds},
		{"-guess-samples has no budget", time.Millisecond, time.Millisecond, 3, 3, 3, stopRounds},
		{"-guess-samples 1", 0, time.Minute, 1, 1, 1, stopRounds},
		{"-guess-samples above the default ceiling", 0, time.Millisecond, sampleRounds + 3, sampleRounds + 3, sampleRounds + 3, stopRounds},
	} {
		sampleBudget = tc.budget
		var mu sync.Mutex
		round := 0
		pad := sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
			mu.Lock()
			round++
			r := round
			mu.Unlock()
			names := make([]string, 100)
			for i := range names {
				names[i] = "g" + strings.Repeat("x", r) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + ".example.org"
			}
			return names, nil
		}}))
		sent := map[string]int{}
		verify := func(_ context.Context, _ string, names []string) ([]string, []string) {
			time.Sleep(time.Duration(len(names)) * tc.perName)
			mu.Lock()
			defer mu.Unlock()
			for _, n := range names {
				sent[n]++
			}
			return names, nil // every guess resolves: only a bound stops it
		}
		c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, GuessSamples: tc.samples, Verify: verify}, pad, fake("real", noKey, true, []string{"www.example.org"}, nil))
		payload, _ := run(t, c, context.Background())
		row := payload["sources"].(map[string]any)["pad"].(map[string]any)
		st := row["rounds"].([]any)
		if len(st) < tc.min || len(st) > tc.max {
			t.Errorf("%s: %d samples checked, want %d to %d (%v)", tc.name, len(st), tc.min, tc.max, row)
		}
		if first := st[0].(map[string]any); first["looked_up"] != float64(100) {
			t.Errorf("%s: the first sample was not checked in full: %v", tc.name, first)
		}
		if len(sent) != 100*len(st) {
			t.Errorf("%s: %d guesses looked up for %d samples", tc.name, len(sent), len(st))
		}
		for n, k := range sent {
			if k != 1 {
				t.Errorf("%s: %s looked up %d times", tc.name, n, k)
			}
		}
		if got, _ := row["sampling_stopped"].(string); got != tc.stopped || row["sampling_bounded"] != true || int(row["sample_ceiling"].(float64)) != sampleCeiling(tc.samples) {
			t.Errorf("%s: stopped %q bounded %v ceiling %v", tc.name, got, row["sampling_bounded"], row["sample_ceiling"])
		}
	}
}

// A source gets 30 seconds by default, subfinder's per-request limit, so a
// run waits no longer for crt.sh than subfinder does.
func TestDefaultSourceTimeoutIsSubfinders(t *testing.T) {
	if got := New(Options{}).opts.SourceTimeout; got != 30*time.Second {
		t.Errorf("default source timeout %s", got)
	}
	if DefaultSourceTimeout != 30*time.Second {
		t.Errorf("DefaultSourceTimeout %s", DefaultSourceTimeout)
	}
}

// A sampled source's next call is made while the last round's names are
// looked up: five rounds of a 300 ms call and a 300 ms check take the longer
// of the two each, 1.8 s, not 3 s.
func TestSampledOverlapsTheCallWithTheCheck(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	pad := sampled(verified(source{name: "pad", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		mu.Lock()
		asked++
		n := asked
		mu.Unlock()
		select {
		case <-time.After(300 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []string{"live" + string(rune('a'+n)) + ".example.org", "dead" + string(rune('a'+n)) + ".example.org"}, nil
	}}))
	c := collector(Options{SourceTimeout: 10 * time.Second, NoHistory: true, GuessSamples: 5, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
		time.Sleep(300 * time.Millisecond)
		var out []string
		for _, n := range names {
			// the fifth round gives no live name; -guess-samples 5 ends the asking
			if strings.HasPrefix(n, "live") && !strings.HasPrefix(n, "livef") {
				out = append(out, n)
			}
		}
		return out, nil
	}}, pad, fake("real", noKey, true, []string{"www.example.org"}, nil))
	t0 := time.Now()
	payload, _ := run(t, c, context.Background())
	took := time.Since(t0)
	if got := len(strs(payload["names"])); got != 5 {
		t.Errorf("%d names, want www and four live: %v", got, payload["names"])
	}
	if took > 2400*time.Millisecond {
		t.Errorf("five rounds took %s: the next call waited for the check", took)
	}
}

// -max-time ends the wait for every source: one that never answers, and a
// sampled source whose rounds keep adding live names. What was gathered is
// kept and listed, and the sources cut say why.
func TestMaxTimeEndsASampledSourceAndOneThatNeverAnswers(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	hang := source{name: "hang", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		<-release // ignores the context, as a source can
		return nil, nil
	}}
	var mu sync.Mutex
	round := 0
	pad := sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		round++
		return []string{"r" + string(rune('a'+round)) + ".example.org"}, nil
	}}))
	c := collector(Options{SourceTimeout: 30 * time.Second, MaxTime: 300 * time.Millisecond, NoHistory: true,
		Verify: func(ctx context.Context, _ string, names []string) ([]string, []string) {
			select { // a lookup that takes long, as a paced resolver does
			case <-time.After(400 * time.Millisecond):
				return names, nil
			case <-ctx.Done():
				return nil, names
			}
		}}, hang, pad, fake("real", noKey, true, []string{"www.example.org"}, nil))
	t0 := time.Now()
	payload, _ := run(t, c, context.Background())
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("-max-time 300ms: the run took %s", d)
	}
	if payload["partial"] != true {
		t.Errorf("not marked partial: %v", payload)
	}
	srcs := payload["sources"].(map[string]any)
	for _, name := range []string{"hang", "pad"} {
		if e, _ := srcs[name].(map[string]any)["error"].(string); !strings.Contains(e, "-max-time") {
			t.Errorf("%s: error %q does not name -max-time", name, e)
		}
	}
	if got := strings.Join(strs(payload["names"]), ","); !strings.Contains(got, "www.example.org") {
		t.Errorf("names %s", got)
	}
}

// subdomain.center holds a pool, and each call gives a random 500 of it:
// the names that resolve are few and a call holds each with the chance
// 500/pool. A reference that asks once keeps what that call held; a run
// that asked again only while a round found a new live name missed such a
// name in a third of its runs. Asking until the names seen are most of the
// estimated pool leaves a name the one call held missing in few runs.
func TestSampledKeepsWhatOneCallHeld(t *testing.T) {
	const trials = 200
	for _, tc := range []struct{ pool, live int }{{1000, 2}, {1000, 6}} {
		pool := make([]string, tc.pool)
		live := map[string]bool{}
		for i := range pool {
			pool[i] = "g" + strings.Repeat("x", i/26) + string(rune('a'+i%26)) + ".example.org"
		}
		for i := 0; i < tc.live; i++ {
			live[pool[i*(tc.pool/tc.live)]] = true
		}
		missed := 0
		for seed := 0; seed < trials; seed++ {
			rng := rand.New(rand.NewSource(int64(seed)))
			sample := func() []string {
				var out []string
				for _, i := range rng.Perm(len(pool))[:500] {
					out = append(out, pool[i])
				}
				return out
			}
			one := sample() // what subfinder | dnsx would have
			var mu sync.Mutex
			pad := sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
				mu.Lock()
				defer mu.Unlock()
				return sample(), nil
			}}))
			c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
				var out []string
				for _, n := range names {
					if live[n] {
						out = append(out, n)
					}
				}
				return out, nil
			}}, pad)
			payload, _ := run(t, c, context.Background())
			got := map[string]bool{}
			for _, n := range strs(payload["names"]) {
				got[n] = true
			}
			for _, n := range one {
				if live[n] && !got[n] {
					missed++
					break
				}
			}
		}
		t.Logf("pool %d, %d live: %d of %d runs lacked a live name one call held", tc.pool, tc.live, missed, trials)
		if missed > trials/10 {
			t.Errorf("pool %d, %d live: %d of %d runs lacked a live name one call held, want at most %d", tc.pool, tc.live, missed, trials, trials/10)
		}
	}
}

// A DNS pass the run's time limit cut short names the limit; it does not say
// the lookups failed (nothing failed), and the row marks the names it left
// and why, for the map and for a resume to read.
func TestCheckCutByTheLimitIsNotAFailedLookup(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"a.example.org", "b.example.org"}, nil)
	pad.verify = true
	c := collector(Options{NoHistory: true, Verify: func(ctx context.Context, _ string, names []string) ([]string, []string) {
		<-ctx.Done() // slow resolvers: the limit ends the pass
		return nil, names
	}}, pad)
	ctx, cancel := context.WithTimeout(context.Background(), emitGrace+400*time.Millisecond)
	defer cancel()
	payload, _ := run(t, c, ctx)
	row := payload["sources"].(map[string]any)["pad"].(map[string]any)
	e, _ := row["error"].(string)
	if strings.Contains(e, "lookups failed") || !strings.Contains(e, types.CutShort) {
		t.Errorf("row error %q: want the time limit named, no failed lookups", e)
	}
	if row[NotCheckedKey] != float64(2) {
		t.Errorf("row %v: not_checked is not 2", row)
	}
	if why, _ := payload[UncheckedWhyKey].(string); why != types.CutShort {
		t.Errorf("unverified_why %q", why)
	}
}

// A run that read the history and wrote to it says where, how many names it
// read and how many it wrote; -w and -permute names are not among them.
func TestRunReportsTheNameHistoryItUsed(t *testing.T) {
	t.Setenv("AZHAQ_DATA_DIR", t.TempDir())
	if _, err := remember(os.Getenv("AZHAQ_DATA_DIR"), "example.org", []string{"old.example.org"}, map[string][]string{"old.example.org": {"x"}}, nil); err != nil {
		t.Fatal(err)
	}
	c := collector(Options{Verify: allLive}, historySource(), fake("a", noKey, true, []string{"www.example.org"}, nil))
	payload, _ := run(t, c, context.Background())
	h, _ := payload[HistoryKey].(map[string]any)
	if h == nil || h["path"] != historyPath(os.Getenv("AZHAQ_DATA_DIR"), "example.org") || h["read"] != float64(1) || h["stored"] != float64(2) {
		t.Errorf("history account %v", h)
	}
	c = collector(Options{NoHistory: true, Verify: allLive}, historySource(), fake("a", noKey, true, []string{"www.example.org"}, nil))
	if payload, _ = run(t, c, context.Background()); payload[HistoryKey] != nil {
		t.Errorf("-no-history left an account: %v", payload[HistoryKey])
	}
}

// With no lookup to make, a sampled source is asked once, as subfinder asks
// it; -guess-samples N asks it up to N times while the names seen are not
// yet most of its pool.
func TestSampledWithoutLookupsTakesTheSamplesTheUserAsksFor(t *testing.T) {
	round := func(names ...string) []string { return names }
	answers := [][]string{
		round("a.example.org", "b.example.org", "c.example.org", "d.example.org"),
		round("c.example.org", "d.example.org", "e.example.org", "f.example.org"),
		round("a.example.org", "e.example.org", "g.example.org", "h.example.org"),
		round("never.example.org"),
	}
	for _, tc := range []struct {
		samples, calls, names int
	}{{0, 1, 4}, {1, 1, 4}, {3, 3, 8}} {
		calls := 0
		s := sampled(source{name: "s", collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
			a := answers[calls]
			calls++
			return a, nil
		}})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ctx = context.WithValue(ctx, samplesKey{}, tc.samples)
		got, err := s.collect(ctx, "example.org", nil, nil) // no checker in ctx: nothing is looked up
		cancel()
		if err != nil || calls != tc.calls || len(got) != tc.names {
			t.Errorf("-guess-samples %d: %d calls and %d names (%v), want %d and %d", tc.samples, calls, len(got), err, tc.calls, tc.names)
		}
	}
}

// Every keyless source that answers is in the default set; one that was dead
// or refused every request at the last check is not.
func TestDefaultSetHoldsTheKeylessSourcesThatAnswer(t *testing.T) {
	deflt := map[string]bool{}
	for _, s := range allSources() {
		deflt[s.name] = s.deflt
	}
	for _, name := range []string{"commoncrawl", "sitedossier", "waybackarchive", "rapiddns", "thc", "hudsonrock"} {
		if !deflt[name] {
			t.Errorf("%s answers without a key and is not in the default set", name)
		}
	}
	for _, name := range []string{"digitorus", "reconcloud", "riddler", "submd", "threatcrowd", "threatminer"} {
		if deflt[name] {
			t.Errorf("%s was dead at the last check and is in the default set", name)
		}
	}
}

// Every guess a run keeps is in the payload's guesses list: the ones no lookup
// answered (also unverified) and the ones the check saw resolve, which a run
// stopped before DNS recorded them would otherwise leave in no list.
func TestPayloadListsEveryGuessItKeeps(t *testing.T) {
	pad := fake("pad", noKey, true, []string{"live.example.org", "slow.example.org", "dead.example.org"}, nil)
	pad.verify = true
	verify := func(_ context.Context, _ string, names []string) ([]string, []string) {
		var live, failed []string
		for _, n := range names {
			switch n {
			case "live.example.org":
				live = append(live, n)
			case "slow.example.org":
				failed = append(failed, n)
			}
		}
		return live, failed
	}
	c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, Verify: verify}, pad, fake("real", noKey, true, []string{"www.example.org"}, nil))
	var payload map[string]any
	if _, err := c.Run(context.Background(), types.Seed{Type: types.TypeDomain, Keys: map[string]string{"domain": "example.org"}}, func(o types.Observation) error {
		return json.Unmarshal(o.Payload, &payload)
	}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(strs(payload["guesses"]), ","); got != "live.example.org,slow.example.org" {
		t.Errorf("guesses %q: want the one that resolved and the one no lookup answered, not the dead one", got)
	}
	if got := strings.Join(strs(payload["unverified"]), ","); got != "slow.example.org" {
		t.Errorf("unverified %q: want only the one no lookup answered", got)
	}
}
