package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Behind countproxy.py, used as -proxy, an origin sees the path of each
// request, as it does behind any forward proxy, not the full address: an
// app server that cannot read an absolute request target (Express turns
// http://host/x into http:/host/x) answers its shell for every script.
func TestCountproxySendsTheOriginThePath(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.RequestURI)
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	proxy, logged := startCountProxy(t, srv)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+proxy))}}
	res, err := c.Get(srv.URL + "/main.js?v=1")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(targets) != 1 || targets[0] != "/main.js?v=1" {
		t.Errorf("the origin was sent %q, want the path and query only", targets)
	}
	if logged() != 1 {
		t.Errorf("the proxy logged %d requests, want 1", logged())
	}
}
