package rdapcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A registry that answers with a stream that never ends is read for 64 KiB
// or 2 s, not until the 6 s of the try, and the run says it was cut.
func TestPullCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
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
	c := &Collector{Client: srv.Client(), BaseURL: srv.URL}
	t0 := time.Now()
	_, _, status, _ := c.pull(context.Background(), srv.URL+"/domain/example.test", "rdap")
	if took := time.Since(t0); took > 4*time.Second || status != 200 {
		t.Errorf("status %d after %s: want the answer's status within 4 s", status, took)
	}
	said := false
	for _, n := range fetch.Notes() {
		said = said || strings.HasPrefix(n, "RDAP ") && strings.Contains(n, "stream that never ends")
	}
	if !said {
		t.Errorf("no note says the answer was cut: %q", fetch.Notes())
	}
}
