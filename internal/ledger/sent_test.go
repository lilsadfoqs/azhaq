package ledger

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A line says a request was written to its connection (or that it reached
// the target and failed): a request a stop cancelled before then has no
// line and is given back to the budget.

func countUnsent(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	old := Unsent
	Unsent = func() { n.Add(1) }
	t.Cleanup(func() { Unsent = old })
	return &n
}

func linesOf(t *testing.T, l *Ledger, path string) []Entry {
	t.Helper()
	l.Close()
	var got []Entry
	if err := Read(path, func(e Entry) error { got = append(got, e); return nil }); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestARequestCancelledBeforeItLeftHasNoLine(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the stop landed after the request was counted
	c := &http.Client{Transport: Wrap(http.DefaultTransport)}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/x", nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("a request with a cancelled context was sent")
	}
	if got := linesOf(t, l, path); len(got) != 0 {
		t.Fatalf("%d lines for a request that never left: %+v", len(got), got)
	}
	if unsent.Load() != 1 || hits.Load() != 0 {
		t.Fatalf("given back %d times, server saw %d requests: want 1 and 0", unsent.Load(), hits.Load())
	}
}

func TestARequestCancelledWhileConnectingToAnAddressNobodyTriedHasNoLine(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The stop lands while the connection is being made, before any connect.
	tr := &http.Transport{DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
		cancel()
		<-dctx.Done()
		return nil, dctx.Err()
	}}
	c := &http.Client{Transport: Wrap(tr)}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9/x", nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("a request with no connection got an answer")
	}
	if got := linesOf(t, l, path); len(got) != 0 {
		t.Fatalf("%d lines for a request that never left: %+v", len(got), got)
	}
	if unsent.Load() != 1 {
		t.Fatalf("given back %d times, want 1", unsent.Load())
	}
}

func TestARequestThatWasWrittenHasOneLineAndIsNotGivenBack(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	// The server reads the request and never answers: the client gives up.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	c := &http.Client{Transport: Wrap(&http.Transport{})}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/slow", nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("no timeout")
	}
	got := linesOf(t, l, path)
	if len(got) != 1 || got[0].Target != srv.URL+"/slow" {
		t.Fatalf("lines %+v, want the one request that was written", got)
	}
	if unsent.Load() != 0 {
		t.Fatalf("a request that left was given back %d times", unsent.Load())
	}
}

func TestAnAnsweredRequestHasOneLine(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: Wrap(&http.Transport{})}
	for i := 0; i < 5; i++ { // the first dials, the rest take the pooled connection
		resp, err := c.Get(srv.URL + "/ok")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if got := linesOf(t, l, path); len(got) != 5 {
		t.Fatalf("%d lines for 5 requests", len(got))
	}
	if unsent.Load() != 0 {
		t.Fatalf("given back %d times", unsent.Load())
	}
}

// A server that takes the connection and closes it at once (a port that is
// not HTTP) was contacted: the request has its line, though it may never have
// been written.
func TestARequestToAServerThatDropsTheConnectionHasALine(t *testing.T) {
	l, path := open(t)
	Use(l)
	defer Use(nil)
	unsent := countUnsent(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c := &http.Client{Transport: Wrap(&http.Transport{DisableKeepAlives: true})}
	for i := 0; i < 20; i++ {
		if resp, err := c.Get("http://" + ln.Addr().String() + "/"); err == nil {
			resp.Body.Close()
			t.Fatal("a server that closed the connection answered")
		}
	}
	if got := linesOf(t, l, path); len(got) != 20 {
		t.Fatalf("%d lines for 20 requests to a server that dropped each connection", len(got))
	}
	if unsent.Load() != 0 {
		t.Fatalf("given back %d times", unsent.Load())
	}
}
