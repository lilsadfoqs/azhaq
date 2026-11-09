package urlcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// An archive that answers with a stream that never ends is read for 64 KiB
// or 2 s, whatever its status, and the run says it was cut.
func TestArchiveCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
		fetch.Reset()
		done := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(status)
			for {
				if _, err := w.Write([]byte("data: tick\n")); err != nil {
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
		}))
		g := &getter{client: srv.Client(), maxPages: 1, retries: 0}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		t0 := time.Now()
		_, _ = g.get(ctx, srv.URL+"/cdx")
		took := time.Since(t0)
		cancel()
		close(done)
		srv.Close()
		if took > 5*time.Second {
			t.Errorf("status %d: the stream held the read for %s", status, took)
		}
		said := false
		for _, n := range fetch.Notes() {
			said = said || strings.HasPrefix(n, "archive ") && strings.Contains(n, "stream that never ends")
		}
		if !said {
			t.Errorf("status %d: no note says the answer was cut: %q", status, fetch.Notes())
		}
		fetch.Reset()
	}
}
