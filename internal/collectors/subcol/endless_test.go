package subcol

import (
	"io"
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

// Whatever a source reads its answer with, a body that never ends is cut at
// the limit, not held to the source's timeout, and the run says which read.
func TestSourceTransportCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	srv := endlessJSON(t)
	cl := &http.Client{Transport: &retryTransport{next: http.DefaultTransport}}
	t0 := time.Now()
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if took := time.Since(t0); took > 4*time.Second || len(b) == 0 {
		t.Errorf("read %d bytes in %s: want the first part within 4 s", len(b), took)
	}
	if !sawCut("source ") {
		t.Errorf("no note says the answer was cut: %q", fetch.Notes())
	}
}
