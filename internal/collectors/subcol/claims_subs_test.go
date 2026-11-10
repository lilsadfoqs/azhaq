package subcol

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// The sources azhaq adds to subfinder's default set are these six and no
// others: they are the ones -extra-wait bounds.
func TestTheSourcesOutsideSubfindersSetAreTheSixTheDocsName(t *testing.T) {
	var extra []string
	for _, s := range allSources() {
		if s.extra {
			extra = append(extra, s.name)
		}
	}
	slices.Sort(extra)
	if want := []string{"commoncrawl", "hudsonrock", "rapiddns", "sitedossier", "thc", "waybackarchive"}; !slices.Equal(extra, want) {
		t.Errorf("extra sources %v, want %v", extra, want)
	}
}

// The sources whose answers are not independent samples of what the sources
// know are the name history and the one that pads its answer, subdomain.center.
func TestDependentSourcesAreTheHistoryAndSubdomainCenter(t *testing.T) {
	var got []string
	for name, dep := range Dependent() {
		if dep {
			got = append(got, name)
		}
	}
	slices.Sort(got)
	if want := []string{"history", "subdomaincenter"}; !slices.Equal(got, want) {
		t.Errorf("dependent %v, want %v", got, want)
	}
}

// The limits the docs state are the ones in force: 200,000 names kept in the
// history and per domain, up to 12 samples of guesses, a 20 s budget for the
// further ones, and 95% of the estimated pool.
func TestDocumentedSamplingAndHistoryLimits(t *testing.T) {
	if maxHistory != 200000 || DefaultMaxNames != 200000 {
		t.Errorf("history keeps %d names, a domain %d", maxHistory, DefaultMaxNames)
	}
	if sampleRounds != 12 || sampleBudget != 20*time.Second || poolCoverage != 0.95 {
		t.Errorf("%d samples, %s budget, %v of the pool", sampleRounds, sampleBudget, poolCoverage)
	}
	if DefaultExtraWait != 5*time.Second {
		t.Errorf("-extra-wait defaults to %s", DefaultExtraWait)
	}
}

// A source that answers 429 is asked again up to three times, each wait at
// most 30 s: a fourth refusal is handed back, and a Retry-After of more than
// 30 s is not waited for.
func TestA429IsAskedAgainThreeTimesAndNeverPastThirtySeconds(t *testing.T) {
	fastPauses(t)
	if maxRetries != 3 || maxRetryWait != 30*time.Second {
		t.Fatalf("%d retries, %s the longest wait", maxRetries, maxRetryWait)
	}
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	resp, err := cl.Get(srv.URL)
	if err != nil || resp.StatusCode != 429 || n.Load() != 4 {
		t.Errorf("%v %v after %d requests, want the 429 handed back after the first and 3 more", resp, err, n.Load())
	}
	n.Store(0)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Retry-After", "31")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer slow.Close()
	t0 := time.Now()
	if resp, err := cl.Get(slow.URL); err != nil || resp.StatusCode != 429 || n.Load() != 1 || time.Since(t0) > time.Second {
		t.Errorf("a Retry-After of 31 s: %v %v, %d requests after %s: it is not waited for", resp, err, n.Load(), time.Since(t0))
	}
}

// A gateway error of crt.sh's JSON API (500, 502, 503, 504) is asked again, up
// to 4 requests in all, with a pause that doubles from 1 s; any other status
// is not. The pauses end where the source's time does.
func TestCrtshGatewayErrorsAreAskedAgainFourTimesWithDoublingPauses(t *testing.T) {
	for _, code := range []string{"500", "502", "503", "504"} {
		if !retry(errors.New("unexpected status code " + code + " received from https://crt.sh/json?q=a.b")) {
			t.Errorf("%s is not asked again", code)
		}
	}
	for _, code := range []string{"400", "404", "501", "429"} {
		if retry(errors.New("unexpected status code " + code + " received from https://crt.sh/json?q=a.b")) {
			t.Errorf("%s is asked again", code)
		}
	}
	if crtshAttempts != 4 || crtshRetryWait != time.Second {
		t.Fatalf("%d attempts from a pause of %s", crtshAttempts, crtshRetryWait)
	}
	oldWait, oldQuery := crtshRetryWait, crtshQuery
	crtshRetryWait = 40 * time.Millisecond
	crtshQuery = func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
		return nil, 0, errors.New("driver: bad connection")
	}
	defer func() { crtshRetryWait, crtshQuery = oldWait, oldQuery }()
	var mu sync.Mutex
	var at []time.Time
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("busy")), Request: r, Header: http.Header{}}, nil
	})}
	sess := &subscraping.Session{Client: client, RequestLimiter: New(Options{}).limiter, Timeout: 5}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := crtshSource().collect(ctx, "example.org", nil, sess); err == nil {
		t.Fatal("503 four times is a failure")
	}
	if len(at) != 4 {
		t.Fatalf("%d requests, want 4", len(at))
	}
	for i, want := range []time.Duration{40, 80, 160} {
		if gap := at[i+1].Sub(at[i]); gap < want*time.Millisecond*9/10 || gap > want*time.Millisecond*3 {
			t.Errorf("pause %d was %s, want about %s", i+1, gap, want*time.Millisecond)
		}
	}
	// With a deadline that the next pause would pass, the request is not made.
	at = nil
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	_, _ = crtshSource().collect(short, "example.org", nil, sess)
	if len(at) < 2 || len(at) >= 4 {
		t.Errorf("%d requests inside a 100 ms source time with pauses of 40, 80, 160 ms: want 2 or 3", len(at))
	}
}

// An HTTP proxy cannot carry PostgreSQL: crt.sh's database is not asked, its
// JSON API is, through the proxy, and the note says why.
func TestCrtshThroughAnHTTPProxyIsAskedInTheJSONAPIOnlyAndSaysSo(t *testing.T) {
	oldWait, oldQuery := crtshRetryWait, crtshQuery
	crtshRetryWait = time.Millisecond
	var dbAsked atomic.Int32
	crtshQuery = func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
		dbAsked.Add(1)
		return []string{"db.example.org"}, 1, nil
	}
	defer func() { crtshRetryWait, crtshQuery = oldWait, oldQuery }()
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			viaProxy.Add(1)
		}
		http.Error(w, "no", http.StatusBadGateway)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	cl := &http.Client{Transport: &retryTransport{next: &http.Transport{Proxy: http.ProxyURL(u)}}, Timeout: 10 * time.Second}
	sess := &subscraping.Session{Client: cl, RequestLimiter: New(Options{}).limiter, Timeout: 5}
	n := &rowNote{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), noteKey{}, n), 20*time.Second)
	defer cancel()
	names, _ := crtshSource().collect(ctx, "example.org", nil, sess)
	if dbAsked.Load() != 0 || len(names) != 0 {
		t.Errorf("the database was asked %d times and gave %v through an HTTP proxy", dbAsked.Load(), names)
	}
	if viaProxy.Load() == 0 {
		t.Errorf("the JSON API was not asked through the proxy")
	}
	if !strings.Contains(n.text, "an http proxy cannot carry PostgreSQL") || !strings.Contains(n.text, "asked the JSON API") {
		t.Errorf("note %q", n.text)
	}
}

// The note says which path gave the names: the exact words of the docs for a
// refused database connection.
func TestCrtshNoteSaysTheDatabaseFailedAndTheJSONAPIWasAsked(t *testing.T) {
	json := `[{"common_name":"c.example.org","name_value":"c.example.org"}]`
	_, note, err := runCrtsh(t, func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
		return nil, 0, errors.New("connection refused")
	}, crtshSession(200, json, new(int)))
	if err != nil || note != "crt.sh database: connection refused; asked the JSON API" {
		t.Errorf("note %q, err %v", note, err)
	}
}

// When every other source has answered with names and crt.sh alone is left,
// it is not asked again, and its row says so.
func TestCrtshNotAskedAgainSaysSoWhenTheOthersAnswered(t *testing.T) {
	oldWait, oldQuery := crtshRetryWait, crtshQuery
	crtshRetryWait = 10 * time.Millisecond
	crtshQuery = func(context.Context, string, *url.URL, time.Duration, int) ([]string, int, error) {
		return nil, 0, errors.New("driver: bad connection")
	}
	defer func() { crtshRetryWait, crtshQuery = oldWait, oldQuery }()
	var asked atomic.Int32
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		asked.Add(1)
		time.Sleep(100 * time.Millisecond)
		return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("Bad Gateway")), Request: r, Header: http.Header{}}, nil
	})}
	c := collector(Options{Client: client, NoHistory: true, SourceTimeout: 10 * time.Second}, crtshSource(), fake("real", noKey, true, []string{"www.example.org"}, nil))
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["crtsh"].(map[string]any)
	if note, _ := row["partial"].(string); !strings.Contains(note, "not asked again: every other source had answered") || asked.Load() != 1 {
		t.Errorf("row %v, %d requests", row, asked.Load())
	}
}

// The error a keyless source's 200 answer gives is the server's own words,
// with the host that said them.
func TestAQuotaPageIsTheSourcesErrorInTheServersWords(t *testing.T) {
	c := collector(Options{NoHistory: true, Client: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("API count exceeded - Increase Quota with Membership")), Request: r, Header: http.Header{}}, nil
	})}}, sourceNamed(t, "hackertarget"))
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["hackertarget"].(map[string]any)
	want := "api.hackertarget.com answered 200 with an error, not names: API count exceeded - Increase Quota with Membership"
	if e, _ := row["error"].(string); e != want {
		t.Errorf("error %q, want %q", e, want)
	}
}

// A sampled source is asked again only while a round gives a name that
// resolves and no other source had: a live name another source gave does not
// count, and the asking ends when the names seen are most of its pool.
func TestSampledDoesNotCountALiveNameAnotherSourceGave(t *testing.T) {
	name := func(i int) string { return "g" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".example.org" }
	span := func(from, to int) []string {
		var out []string
		for i := from; i < to; i++ {
			out = append(out, name(i))
		}
		return out
	}
	// The one name that resolves is first seen in the second round, and the
	// real source gave it too; a third round would hold another.
	rounds := [][]string{span(0, 100), span(1, 101), span(2, 102)}
	known := name(100)
	asked := 0
	realGave := make(chan struct{})
	pad := sampled(verified(source{name: "pad", deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		if asked == 1 {
			// The scene: the real source gave the name before the second
			// sample is checked. Its names reach the checker just after its
			// call returns.
			<-realGave
			time.Sleep(50 * time.Millisecond)
		}
		r := rounds[min(asked, len(rounds)-1)]
		asked++
		return r, nil
	}}))
	realSrc := source{name: "real", need: noKey, deflt: true, collect: func(context.Context, string, []string, *subscraping.Session) ([]string, error) {
		defer close(realGave)
		return []string{known}, nil
	}}
	c := collector(Options{SourceTimeout: 5 * time.Second, NoHistory: true, Verify: func(_ context.Context, _ string, names []string) ([]string, []string) {
		var out []string
		for _, n := range names {
			if n == known {
				out = append(out, n)
			}
		}
		return out, nil
	}}, pad, realSrc)
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["pad"].(map[string]any)
	if got := len(row["rounds"].([]any)); got != 2 || row["sampling_stopped"] != stopNoLive {
		t.Errorf("%d samples checked, stopped %q: the live name was another source's, so the second sample found nothing new", got, row["sampling_stopped"])
	}
}

// -source-timeout bounds each call of a sampled source and, with them, half
// the time it spends asking; the lookups of its guesses are not bounded by it.
func TestSampledAskingIsBoundedByHalfTheSourceTimeoutAndLookupsAreNot(t *testing.T) {
	var round atomic.Int32
	pad := sampled(verified(source{name: "pad", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		r := int(round.Add(1))
		time.Sleep(600 * time.Millisecond)
		return []string{"live" + strings.Repeat("x", r) + ".example.org"}, nil
	}}))
	var deadline atomic.Bool
	c := collector(Options{SourceTimeout: 2 * time.Second, NoHistory: true, GuessSamples: 10, Verify: func(ctx context.Context, _ string, names []string) ([]string, []string) {
		if _, ok := ctx.Deadline(); ok {
			deadline.Store(true)
		}
		time.Sleep(300 * time.Millisecond)
		return names, nil
	}}, pad)
	payload, _ := run(t, c, context.Background())
	row := payload["sources"].(map[string]any)["pad"].(map[string]any)
	// 600 ms a call: the second call makes 1.2 s of asking, past half of 2 s.
	if got := len(row["rounds"].([]any)); got != 2 || row["sampling_stopped"] != stopTime || row["sampling_bounded"] != true {
		t.Errorf("%d samples, stopped %q: asking ends at half the source's time", got, row["sampling_stopped"])
	}
	if deadline.Load() {
		t.Error("the lookups of the guesses carry a deadline from -source-timeout")
	}
	// A call that takes longer than -source-timeout is cut at it.
	slow := sampled(verified(source{name: "slow", deflt: true, collect: func(ctx context.Context, _ string, _ []string, _ *subscraping.Session) ([]string, error) {
		select {
		case <-time.After(20 * time.Second):
			return []string{"late.example.org"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}))
	t0 := time.Now()
	payload, _ = run(t, collector(Options{SourceTimeout: 2 * time.Second, NoHistory: true, Verify: allLive}, slow), context.Background())
	if took := time.Since(t0); took > 5*time.Second || payload["sources"].(map[string]any)["slow"].(map[string]any)["error"] == nil {
		t.Errorf("a call of 20 s under a -source-timeout of 2 s took %s: %v", took, payload["sources"])
	}
}
