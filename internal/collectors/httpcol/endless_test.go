package httpcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// The h2c upgrade probe reads its answer for 64 KiB or 2 s: a stream that
// never ends does not hold it, and the run says it was cut.
func TestHTTP2ProbeCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	done := make(chan struct{})
	defer close(done)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
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
	defer srv.Close()
	c := &Collector{Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	if c.supportsHTTP2(ctx, srv.URL+"/") {
		t.Error("a plain stream taken for an h2c upgrade")
	}
	if took := time.Since(t0); took > 5*time.Second {
		t.Errorf("the stream held the probe for %s", took)
	}
	said := false
	for _, n := range fetch.Notes() {
		said = said || strings.HasPrefix(n, "h2c probe ") && strings.Contains(n, "stream that never ends")
	}
	if !said {
		t.Errorf("no note says the answer was cut: %q", fetch.Notes())
	}
}
