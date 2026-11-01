package egress

import (
	"net/http"
	"net/url"
	"testing"
)

func envReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func TestEnvProxyLoopbackFollowsTheEnvironmentWhenAsked(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18888")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18889")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Cleanup(func() { ProxyLoopback = false })

	ProxyLoopback = false
	if u, _ := envProxy(envReq(t, "http://127.0.0.1:3001/")); u != nil {
		t.Errorf("Go's rule keeps loopback direct, got %v", u)
	}
	ProxyLoopback = true
	for raw, want := range map[string]string{
		"http://127.0.0.1:3001/":  "http://127.0.0.1:18888",
		"https://127.0.0.1:3001/": "http://127.0.0.1:18889",
		"http://localhost/":       "http://127.0.0.1:18888",
		"http://[::1]:80/":        "http://127.0.0.1:18888",
	} {
		u, err := envProxy(envReq(t, raw))
		if err != nil || u == nil || u.String() != want {
			t.Errorf("%s: proxy %v, %v, want %s", raw, u, err, want)
		}
	}

	t.Setenv("NO_PROXY", "localhost,127.0.0.1:3002,10.0.0.0/8")
	for raw, via := range map[string]bool{
		"http://localhost:3001/":  false,
		"http://127.0.0.1:3002/":  false,
		"http://127.0.0.1:3001/":  true,
		"http://127.0.0.2:3002/":  true,
		"http://127.0.0.1:3003/x": true,
	} {
		u, _ := envProxy(envReq(t, raw))
		if (u != nil) != via {
			t.Errorf("NO_PROXY set, %s: proxy %v, want through the proxy: %v", raw, u, via)
		}
	}
	t.Setenv("NO_PROXY", "*")
	if u, _ := envProxy(envReq(t, "http://127.0.0.1:3001/")); u != nil {
		t.Errorf("NO_PROXY=*: %v", u)
	}
}

func TestNoProxyMatches(t *testing.T) {
	for _, c := range []struct {
		spec, host, port, scheme string
		want                     bool
	}{
		{".example.com", "a.example.com", "", "https", true},
		{"example.com", "example.com", "", "https", true},
		{"example.com:8443", "example.com", "443", "https", false},
		{"127.0.0.0/8", "127.0.0.9", "80", "http", true},
		{"::1", "::1", "80", "http", true},
		{"", "127.0.0.1", "80", "http", false},
	} {
		if got := noProxyMatches(c.spec, c.host, c.port, c.scheme); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}
