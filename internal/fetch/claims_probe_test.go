package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A route that streams for ever is answered with its status, headers and the
// first part of its body: up to 64 KiB, or what comes in 2 seconds, and then
// closed; its body counts as truncated. Server-sent events and
// multipart/x-mixed-replace both do.
func TestAStreamIsCutAt64KiBOrTwoSeconds(t *testing.T) {
	Reset()
	defer Reset()
	done := make(chan struct{})
	defer close(done)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flood": // far more than 64 KiB, at once
			w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=x")
			chunk := strings.Repeat("a", 4096)
			for i := 0; i < 1024; i++ {
				if _, err := w.Write([]byte(chunk)); err != nil {
					return
				}
			}
			<-r.Context().Done()
		case "/trickle": // 10 bytes every 300 ms
			w.Header().Set("Content-Type", "text/event-stream")
			for {
				if _, err := w.Write([]byte("data: 123\n")); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-done:
					return
				case <-r.Context().Done():
					return
				case <-time.After(300 * time.Millisecond):
				}
			}
		}
	}))
	defer srv.Close()
	t0 := time.Now()
	res, _, err := Do(context.Background(), srv.Client(), srv.URL+"/flood")
	if err != nil || res.Status != 200 || len(res.Body) != 64<<10 || !res.Truncated || time.Since(t0) > time.Second {
		t.Errorf("a flood: %v, status %d, %d bytes, truncated %v after %s: want 64 KiB, truncated, at once", err, res.Status, len(res.Body), res.Truncated, time.Since(t0))
	}
	t0 = time.Now()
	res, _, err = Do(context.Background(), srv.Client(), srv.URL+"/trickle")
	took := time.Since(t0)
	if err != nil || res.Status != 200 || !res.Truncated || took < 1800*time.Millisecond || took > 4*time.Second {
		t.Errorf("a trickle: %v, status %d, truncated %v after %s: want what came in 2 s", err, res.Status, res.Truncated, took)
	}
	if n := len(res.Body); n < 50 || n > 100 || !strings.HasPrefix(string(res.Body), "data: 123\n") {
		t.Errorf("a trickle gave %d bytes %q: want the first part of it, about 7 writes of 10 bytes", n, res.Body)
	}
}
