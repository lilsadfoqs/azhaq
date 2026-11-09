package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestBoundNoteSaysItCut: a reader that reads the body itself gets the same
// cut as Do, and the run's summary says so; an ordinary answer is left alone.
func TestBoundNoteSaysItCut(t *testing.T) {
	Reset()
	defer Reset()
	done := make(chan struct{})
	defer close(done)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/plain" {
			_, _ = w.Write([]byte("whole"))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for {
			if _, err := w.Write([]byte("data: 1\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	for path, wantNote := range map[string]bool{"/plain": false, "/stream": true} {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		BoundNote(resp, "test "+path)
		t0 := time.Now()
		buf := make([]byte, 1<<10)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				break
			}
		}
		resp.Body.Close()
		cancel()
		if took := time.Since(t0); took > 4*time.Second {
			t.Errorf("%s: read held for %s", path, took)
		}
		said := false
		for _, n := range Notes() {
			if strings.HasPrefix(n, "test "+path+":") && strings.Contains(n, "stream that never ends") {
				said = true
			}
		}
		if said != wantNote {
			t.Errorf("%s: note %v, want %v (%q)", path, said, wantNote, Notes())
		}
	}
}
