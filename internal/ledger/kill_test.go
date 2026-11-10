package ledger

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/neterr"
)

// A request the kill file refused at its dial never left: no line, and it is
// given back, although nothing cancelled its context.
func TestARequestTheKillFileRefusedAtTheDialHasNoLine(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, &neterr.Killed{Path: "kill"}
	}}
	c := &http.Client{Transport: Wrap(tr)}
	if resp, err := c.Get("http://127.0.0.1:9/x"); err == nil {
		resp.Body.Close()
		t.Fatal("a refused dial answered")
	}
	if got := linesOf(t, l, path); len(got) != 0 {
		t.Fatalf("%d lines for a request the kill file refused before it left: %+v", len(got), got)
	}
	if unsent.Load() != 1 {
		t.Fatalf("given back %d times, want 1", unsent.Load())
	}
}

// Once the kill file exists, a request let go before it that found its
// pooled connection closed is made again (IsReplay lets its dial through),
// and the server gets what the ledger lists: one line per request it read.
func TestAReplayAfterTheKillFileListsWhatTheServerGot(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	var killed atomic.Bool
	d := &net.Dialer{}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if killed.Load() && !IsReplay(ctx) {
			return nil, &neterr.Killed{Path: "kill"}
		}
		return d.DialContext(ctx, network, addr)
	}}
	c := &http.Client{Transport: Wrap(tr)}
	for i := 0; i < 2; i++ {
		resp, err := c.Get(srv.URL + "/x")
		if err == nil {
			resp.Body.Close()
		}
		if i == 0 {
			srv.CloseClientConnections() // the pooled connection is closed under the client
			killed.Store(true)
		}
	}
	got := linesOf(t, l, path)
	if int64(len(got)) != hits.Load() || unsent.Load() != 2-hits.Load() {
		t.Fatalf("server read %d requests, ledger %d lines, %d given back: the ledger is what the server got", hits.Load(), len(got), unsent.Load())
	}
}
