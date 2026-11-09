package gqlcol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// A query answered by a stream that never ends is read for 64 KiB or 2 s,
// not until the request's own timeout, and the run says it was cut.
func TestQueryCutsAnEndlessAnswerAndSaysSo(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	status, data, err := NewSchema(srv.Client()).post(ctx, srv.URL+"/graphql", "{__typename}")
	if took := time.Since(t0); err != nil || status != 200 || took > 5*time.Second || !strings.HasPrefix(string(data), "data: tick") {
		t.Errorf("status %d, %d bytes, %v after %s: want the first part of the stream within 5 s", status, len(data), err, took)
	}
	said := false
	for _, n := range fetch.Notes() {
		said = said || strings.HasPrefix(n, "GraphQL "+srv.URL+"/graphql:") && strings.Contains(n, "stream that never ends")
	}
	if !said {
		t.Errorf("no note says the answer was cut: %q", fetch.Notes())
	}
}
