package subcol

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/subdomaincenter"
)

func fastPauses(t *testing.T) {
	old := firstPause
	firstPause = 10 * time.Millisecond
	t.Cleanup(func() { firstPause = old })
}

// A 429 is asked again after its Retry-After, and the row says so.
func TestRetryAfterIsWaitedOut(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	var first, second time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			first = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			second = time.Now()
			io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	if gap := second.Sub(first); gap < 950*time.Millisecond {
		t.Errorf("asked again after %s, Retry-After said 1s", gap)
	}
	row := map[string]any{}
	th.fields(row)
	if row["retried_429"] != 1 || row["retry_after_seconds"] != 1.0 || row["gave_up_429"] != nil {
		t.Errorf("row %v", row)
	}
}

// Without a Retry-After the pause grows; a source that keeps refusing is
// handed back its 429 and the row says it gave up.
func TestRetryGivesUpAndSaysSo(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 429 {
		t.Fatalf("%v %v", resp, err)
	}
	if n.Load() != maxRetries+1 {
		t.Errorf("%d requests, want %d", n.Load(), maxRetries+1)
	}
	row := map[string]any{}
	th.fields(row)
	if row["gave_up_429"] != true || row["retried_429"] != maxRetries {
		t.Errorf("row %v", row)
	}
}

// A Retry-After longer than the source has left, or than is worth taking,
// is not waited for: the 429 comes back at once with the wait it asked.
func TestRetryAfterTooLongIsNotWaitedFor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	t0 := time.Now()
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 429 || time.Since(t0) > time.Second {
		t.Fatalf("%v %v after %s", resp, err, time.Since(t0))
	}
	row := map[string]any{}
	th.fields(row)
	if row["retry_after_seconds"] != 120.0 || row["gave_up_429"] != true || row["retried_429"] != nil {
		t.Errorf("row %v", row)
	}
}

// A POST is sent again with its body.
func TestRetryResendsTheBody(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		got = string(b)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	resp, err := cl.Post(srv.URL, "text/plain", strings.NewReader("payload"))
	if err != nil || resp.StatusCode != 200 || got != "payload" {
		t.Fatalf("%v %v %q", resp, err, got)
	}
}

func TestRetryAfterHeader(t *testing.T) {
	if d, ok := retryAfter("7"); !ok || d != 7*time.Second {
		t.Errorf("seconds: %v %v", d, ok)
	}
	at := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	if d, ok := retryAfter(at); !ok || d < 3*time.Second || d > 6*time.Second {
		t.Errorf("date: %v %v", d, ok)
	}
	if _, ok := retryAfter("soon"); ok {
		t.Error("junk accepted")
	}
}

// -source-rate caps every source, a source's own lower default stays, and
// -source-rates names one source and wins.
func TestSourceRates(t *testing.T) {
	took := func(o Options, name string, n int) time.Duration {
		c := New(o)
		t0 := time.Now()
		for range n {
			if err := c.limiter.Wait(context.Background(), name); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(t0)
	}
	if d := took(Options{}, "crtname", 5); d > 50*time.Millisecond {
		t.Errorf("no cap: %s", d)
	}
	if d := took(Options{SourceRate: 20}, "crtname", 4); d < 140*time.Millisecond {
		t.Errorf("-source-rate 20: 4 requests in %s", d)
	}
	// hackertarget's own 2/s is below 20/s and stays.
	if d := took(Options{SourceRate: 20}, "hackertarget", 2); d < 450*time.Millisecond {
		t.Errorf("own default lost: %s", d)
	}
	if d := took(Options{SourceRate: 2, SourceRates: map[string]float64{"crtname": 100}}, "crtname", 5); d > 100*time.Millisecond {
		t.Errorf("-source-rates did not win: %s", d)
	}
}

// A busy server (503, and the other 5xx but 501 and 505) is asked again as
// a 429 is, and the row counts the retries as its own.
func TestAServerErrorIsAskedAgain(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error": "server busy (64 queries in flight)"}`)
			return
		}
		io.WriteString(w, `["a.example.org"]`)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 200 || n.Load() != 3 {
		t.Fatalf("%v %v after %d requests", resp, err, n.Load())
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != `["a.example.org"]` {
		t.Errorf("body %q", b)
	}
	row := map[string]any{}
	th.fields(row)
	if row["retried_5xx"] != 2 || row["gave_up_5xx"] != nil || row["rate_limited"] != nil || row["requests"] != 3 {
		t.Errorf("row %v", row)
	}
	for _, code := range []int{500, 502, 503, 504, 522} {
		if !busy(code) {
			t.Errorf("%d is not asked again", code)
		}
	}
	for _, code := range []int{200, 400, 403, 404, 501, 505} {
		if busy(code) {
			t.Errorf("%d is asked again", code)
		}
	}
}

// A server that stays busy is handed back its 503 after the retries, with
// its words, and the row says it gave up.
func TestAServerErrorThatStaysIsHandedBackWithItsWords(t *testing.T) {
	fastPauses(t)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "Service busy, try later")
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th, log := &throttle{}, &statusLog{}
	ctx := context.WithValue(withThrottle(context.Background(), th), statusKey{}, log)
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := cl.Do(req)
	if err != nil || resp.StatusCode != 503 || n.Load() != maxRetries+1 {
		t.Fatalf("%v %v after %d requests", resp, err, n.Load())
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "Service busy, try later" {
		t.Errorf("the source's body was changed: %q", b)
	}
	row := map[string]any{}
	th.fields(row)
	if row["gave_up_5xx"] != true || row["retried_5xx"] != maxRetries {
		t.Errorf("row %v", row)
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	got := withWords(ctx, "unexpected status code 503 received from "+srv.URL+"/x?a=1")
	if want := host + " answered 503: Service busy, try later"; got != want {
		t.Errorf("reason %q, want %q", got, want)
	}
}

// A 501 or a 404 is not a busy server: one request, and the words are kept.
func TestAnAnswerThatIsNotBusyIsAskedOnce(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	req, _ := http.NewRequestWithContext(withThrottle(context.Background(), th), "GET", srv.URL, nil)
	if resp, err := cl.Do(req); err != nil || resp.StatusCode != 501 || n.Load() != 1 {
		t.Fatalf("%v %v after %d requests", resp, err, n.Load())
	}
	row := map[string]any{}
	th.fields(row)
	if row["retried_5xx"] != nil || row["gave_up_5xx"] != nil {
		t.Errorf("row %v", row)
	}
}

// The retries stay within the source's time: a pause that would end past
// its deadline is not taken.
func TestServerErrorRetriesStayWithinTheSourceTime(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	th := &throttle{}
	ctx, cancel := context.WithTimeout(withThrottle(context.Background(), th), 2*time.Second)
	defer cancel()
	t0 := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	if resp, err := cl.Do(req); err != nil || resp.StatusCode != 502 || n.Load() != 1 || time.Since(t0) > time.Second {
		t.Fatalf("%v %v after %d requests, %s", resp, err, n.Load(), time.Since(t0))
	}
	row := map[string]any{}
	th.fields(row)
	if row["gave_up_5xx"] != true {
		t.Errorf("row %v", row)
	}
}

// subdomain.center's busy answer, as it gave it: the source's failure
// carries the status and the server's words, and a 503 that clears within
// the retries gives the names.
func TestSubdomainCenterBusyAnswerIsRetriedAndQuoted(t *testing.T) {
	fastPauses(t)
	for _, c := range []struct {
		name  string
		busy  int // 503s before the names
		names int
		why   string
	}{
		{"clears", 2, 2, ""},
		{"stays", 99, 0, `api.subdomain.center answered 503: server busy (64 queries in flight)`},
	} {
		var n atomic.Int32
		cl := &http.Client{Transport: &retryTransport{next: rtFunc(func(r *http.Request) (*http.Response, error) {
			h := http.Header{}
			if int(n.Add(1)) <= c.busy {
				return &http.Response{StatusCode: 503, Header: h, Request: r,
					Body: io.NopCloser(strings.NewReader(`{"error": "server busy (64 queries in flight)"}`))}, nil
			}
			return &http.Response{StatusCode: 200, Header: h, Request: r,
				Body: io.NopCloser(strings.NewReader(`["www.hackerone.com","api.hackerone.com"]`))}, nil
		})}}
		sess, err := subscraping.NewSession("hackerone.com", "", nil, 5)
		if err != nil {
			t.Fatal(err)
		}
		sess.Client, sess.RequestLimiter = cl, New(Options{}).limiter
		ctx := withThrottle(context.WithValue(context.Background(), statusKey{}, &statusLog{}), &throttle{})
		names, err := pd(func() subscraping.Source { return &subdomaincenter.Source{} }, 0).collect(ctx, "hackerone.com", nil, sess)
		if len(names) != c.names || (c.why == "") != (err == nil) || (err != nil && err.Error() != c.why) {
			t.Errorf("%s: %d names, error %v after %d requests", c.name, len(names), err, n.Load())
		}
	}
}
