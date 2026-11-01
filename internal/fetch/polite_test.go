package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trannghiach/azhaq/internal/egress"
)

func TestBackoffAsksAgainAfter429(t *testing.T) {
	Reset()
	defer Reset()
	backoffBase = 5 * time.Millisecond
	defer func() { backoffBase = time.Second }()
	Backoff = true
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/x")
	if err != nil || res.Status != 200 || n.Load() != 3 {
		t.Fatalf("%v %d after %d requests", err, res.Status, n.Load())
	}
	if notes := strings.Join(Notes(), "\n"); !strings.Contains(notes, "answered 429 with 2 requests") {
		t.Errorf("the summary does not say a host slowed the run: %q", notes)
	}
}

func TestBackoffGivesUpAndSaysSo(t *testing.T) {
	Reset()
	defer Reset()
	backoffBase = time.Millisecond
	defer func() { backoffBase = time.Second }()
	Backoff = true
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/x")
	if err != nil || res.Status != 503 || n.Load() != backoffTries+1 {
		t.Fatalf("%v %d after %d", err, res.Status, n.Load())
	}
	if notes := strings.Join(Notes(), "\n"); !strings.Contains(notes, "still got it after") {
		t.Errorf("a request that stays refused is not said: %q", notes)
	}
}

// Only 429 and 503 say "wait": a 500 or a 502 is the answer and is not asked
// again, so a route that errors costs one request.
func TestBackoffDoesNotRetryOtherServerErrors(t *testing.T) {
	Reset()
	defer Reset()
	backoffBase = time.Millisecond
	defer func() { backoffBase = time.Second }()
	Backoff = true
	Retry = 1
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if strings.HasSuffix(r.URL.Path, "/gateway") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	for _, p := range []string{"/boom", "/gateway"} {
		before := n.Load()
		res, _, err := Do(context.Background(), srv.Client(), srv.URL+p)
		if err != nil || res.Status < 500 || n.Load()-before != 1 {
			t.Errorf("%s: %v, status %d after %d requests", p, err, res.Status, n.Load()-before)
		}
	}
}

func TestWithoutBackoffA429IsTheAnswer(t *testing.T) {
	Reset()
	defer Reset()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if res, _, _ := Do(context.Background(), srv.Client(), srv.URL+"/x"); res.Status != 429 || n.Load() != 1 {
		t.Errorf("%d after %d requests", res.Status, n.Load())
	}
}

func TestCookieJarCarriesWhatTheTargetSets(t *testing.T) {
	Reset()
	defer Reset()
	UseJar(true)
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
			return
		}
		got.Store(r.Header.Get("Cookie"))
	}))
	defer srv.Close()
	ctx := context.Background()
	_, _, _ = Do(ctx, srv.Client(), srv.URL+"/first")
	_, _, _ = Do(ctx, srv.Client(), srv.URL+"/second")
	if c, _ := got.Load().(string); c != "sid=abc" {
		t.Errorf("Cookie: %q", c)
	}
}

func TestMaxPerHostStopsWithTheBudgetError(t *testing.T) {
	Reset()
	defer Reset()
	MaxPerHost = 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	var last error
	for _, p := range []string{"/a", "/b", "/c"} {
		_, _, last = Do(context.Background(), srv.Client(), srv.URL+p)
	}
	if last == nil || !strings.Contains(last.Error(), "budget") {
		t.Errorf("third request: %v", last)
	}
	if !strings.Contains(strings.Join(Notes(), "\n"), "-max-host-requests 2") {
		t.Error("the cap is not in the summary")
	}
}

func TestSubmitFormIsCountedAndHeldToScope(t *testing.T) {
	Reset()
	defer Reset()
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		body.Store(r.Method + " " + string(b[:n]))
	}))
	defer srv.Close()
	if _, err := SubmitForm(context.Background(), srv.Client(), srv.URL+"/login", "u=azhaq"); err != nil {
		t.Fatal(err)
	}
	if v, _ := body.Load().(string); v != "POST u=azhaq" || Posts() != 1 {
		t.Errorf("%q, %d posts", v, Posts())
	}
	egress.SetScope(func(string) bool { return false })
	if _, err := SubmitForm(context.Background(), srv.Client(), srv.URL+"/login", "u=azhaq"); err == nil || Posts() != 1 {
		t.Errorf("a submission outside the scope was sent: %v", err)
	}
}

// A route that streams events forever answers with its status, headers and
// the first part of its body at once, not when the request times out.
func TestEventStreamDoesNotHoldTheRequest(t *testing.T) {
	Reset()
	defer Reset()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer srv.Close()
	defer close(done)
	start := time.Now()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/events")
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the stream held the request for %v", took)
	}
	if res.Status != 200 || !strings.HasPrefix(string(res.Body), "data: tick") || !res.Truncated {
		t.Errorf("status %d, truncated %v, body %q", res.Status, res.Truncated, res.Body)
	}
}
