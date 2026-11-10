package searchcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// endlessJSON serves an array that never closes: 100 KiB at once, then
// nothing, as a server that trickles forever would.
func endlessJSON(t *testing.T) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("[" + strings.Repeat("1,", 50<<10)))
		w.(http.Flusher).Flush()
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sawCut(prefix string) bool {
	for _, n := range fetch.Notes() {
		if strings.HasPrefix(n, prefix) && strings.Contains(n, "stream that never ends") {
			return true
		}
	}
	return false
}

// A search engine answering with a stream that never ends is cut at the
// limit, not held to the run's timeout, and the run says which read was cut.
func TestGetJSONCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	srv := endlessJSON(t)
	var v any
	t0 := time.Now()
	_ = getJSON(context.Background(), srv.Client(), srv.URL+"/search", nil, &v)
	if took := time.Since(t0); took > 4*time.Second {
		t.Errorf("held for %s by an answer that never ends", took)
	}
	if !sawCut("search ") {
		t.Errorf("no note says the answer was cut: %q", fetch.Notes())
	}
}
