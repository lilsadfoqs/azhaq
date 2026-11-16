package httprow

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/egress"
)

// Only a detection the identity headers produced is marked, and only when the
// run's proxy could not be asked for its own answer.
func TestMarkViaProxyMarksWhatOnlyAHeaderNamed(t *testing.T) {
	egress.Reset()
	defer egress.Reset()
	rows := func() []map[string]string {
		return []map[string]string{{"product": "nginx", "version": "1.25.3", "template": "nginx-version"}, {"product": "Grafana", "template": "grafana-detect"}}
	}
	again := func(h http.Header) []map[string]string { // the page itself names Grafana; the header alone named nginx
		if h.Get("Server") != "" {
			t.Errorf("the headers were not stripped of the identity ones: %v", h)
		}
		return rows()[1:]
	}
	h := http.Header{"Server": {"nginx/1.25.3"}}

	got := rows()
	MarkViaProxy(got, h, again)
	if got[0]["via_proxy"] != "" {
		t.Errorf("marked with no proxy: %v", got)
	}

	// A proxy that hangs up on a request addressed to it cannot be asked.
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
	pu, _ := url.Parse("http://" + ln.Addr().String())
	egress.SetTargetProxy(pu)
	_, _ = egress.TargetClient(egress.TargetOptions{Timeout: 2 * time.Second}).Get("http://127.0.0.1:9/")
	if !egress.ProxyUnasked() {
		t.Fatal("the proxy was asked")
	}
	got = rows()
	MarkViaProxy(got, h, again)
	if got[0]["via_proxy"] != "1" || got[1]["via_proxy"] != "" {
		t.Errorf("rows %v: want nginx marked and Grafana not", got)
	}
}
