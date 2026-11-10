package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
)

// endlessAdvisoryFeed serves an array that never closes: 100 KiB at once, then
// nothing, as a server that trickles forever would.
func endlessAdvisoryFeed(t *testing.T) *httptest.Server {
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

func sawAdvisoryCut(prefix string) bool {
	for _, n := range fetch.Notes() {
		if strings.HasPrefix(n, prefix) && strings.Contains(n, "stream that never ends") {
			return true
		}
	}
	return false
}

// An advisory feed that never ends is cut at the limit, not held to the
// source's timeout, and the run says which read was cut.
func TestLoadAdvisoriesCutsAnEndlessFeedAndSaysSo(t *testing.T) {
	fetch.Reset()
	defer fetch.Reset()
	srv := endlessAdvisoryFeed(t)
	t0 := time.Now()
	_, _ = loadAdvisories(context.Background(), srv.URL)
	if took := time.Since(t0); took > 4*time.Second {
		t.Errorf("held for %s by a feed that never ends", took)
	}
	if !sawAdvisoryCut("advisory source ") {
		t.Errorf("no note says the feed was cut: %q", fetch.Notes())
	}
}
