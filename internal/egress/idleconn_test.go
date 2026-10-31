package egress

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// closingServer answers, then closes the connection without saying so
// (no Connection: close): what a proxy that drops idle connections does.
func closingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		n.Add(1)
		fmt.Fprint(w, "ok")
	}))
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateIdle {
			c.Close()
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &n
}

// A request is in the ledger and the count when it is written to a live
// connection: one written to a connection the server had closed is not sent,
// and its replacement is the request.
func TestRequestsOnConnectionsTheServerClosedAreCountedOnce(t *testing.T) {
	Reset()
	defer Reset()
	entries := withLedger(t)
	srv, hits := closingServer(t)
	c := TargetClient(TargetOptions{})
	const workers, each = 8, 100
	const n = workers * each
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				var resp *http.Response
				var err error
				if i%2 == 0 {
					resp, err = c.Post(srv.URL, "application/x-www-form-urlencoded", strings.NewReader("a=b"))
				} else {
					resp, err = c.Get(srv.URL)
				}
				if err != nil {
					t.Errorf("request %d: %v", i, err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if int(hits.Load()) != n {
		t.Fatalf("the server got %d requests, sent %d", hits.Load(), n)
	}
	if got := entries(); len(got) != n {
		t.Fatalf("the ledger holds %d lines for %d requests the server got", len(got), n)
	}
}
