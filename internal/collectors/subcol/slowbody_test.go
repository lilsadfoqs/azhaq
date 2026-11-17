package subcol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func dripServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`["a.example.org",`))
		w.(http.Flusher).Flush()
		for i := 0; i < 60; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
			_, _ = w.Write([]byte(" "))
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pagerServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Truncated", "true")
		w.Header().Set("X-Next-Offset", fmt.Sprint(time.Now().UnixNano()))
		_, _ = w.Write([]byte(fmt.Sprintf(`["p%d.example.org"]`, time.Now().UnixNano())))
		time.Sleep(50 * time.Millisecond)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A source whose answer drips in, or pages for ever, is cut at
// -source-timeout, keeps the names it read, and is named as cut by it: the
// sampled one (subdomain.center) too, whose own calls end the same way.
func TestSlowOrEndlessSourceIsCutAndNamedAtSourceTimeout(t *testing.T) {
	drip, pager := dripServer(t), pagerServer(t)
	const bound = time.Second
	for _, c := range []struct {
		name, host string
		keys       []string
		names      bool
	}{
		{"subdomaincenter", drip.URL, nil, false},
		{"subdomaincenter", pager.URL, []string{"k"}, true},
		{"anubis", drip.URL, nil, false},
	} {
		cl := &http.Client{Transport: toServer{strings.TrimPrefix(c.host, "http://")}}
		o := Options{Client: cl, SourceTimeout: bound, NoHistory: true, Only: []string{c.name}}
		if c.keys != nil {
			o.Keys = map[string][]string{c.name: c.keys}
		}
		t0 := time.Now()
		payload, _ := run(t, New(o), context.Background())
		if took := time.Since(t0); took > bound+time.Second {
			t.Errorf("%s keys %v: the run took %s with -source-timeout %s", c.name, c.keys, took, bound)
		}
		row, _ := payload["sources"].(map[string]any)[c.name].(map[string]any)
		if e, _ := row["error"].(string); e != "no answer in 1s (-source-timeout)" {
			t.Errorf("%s keys %v: the cut is named %q", c.name, c.keys, e)
		}
		if n, _ := row["count"].(float64); c.names && n == 0 {
			t.Errorf("%s keys %v: the names read before the cut are lost: %v", c.name, c.keys, row)
		}
	}
}
