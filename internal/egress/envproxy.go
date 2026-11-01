package egress

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/http/httpproxy"
)

// ProxyLoopback makes the environment's proxy apply to loopback targets
// too, as curl and Burp-in-the-shell users expect (NO_PROXY keeps some
// direct). Go skips them whatever the variables say. The commands turn it
// on; a library caller and the tests keep Go's rule.
var ProxyLoopback bool

var envState struct {
	mu   sync.Mutex
	key  string
	cfg  *httpproxy.Config
	skip []string
	fn   func(*url.URL) (*url.URL, error)
}

func envVar(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// envProxy is the proxy the environment names for r (HTTP_PROXY,
// HTTPS_PROXY, NO_PROXY, either case), nil for none. The variables are read
// as they stand, not once for the process.
func envProxy(r *http.Request) (*url.URL, error) {
	if !ProxyLoopback || r.URL == nil || !isLoopback(r.URL.Hostname()) {
		return http.ProxyFromEnvironment(r)
	}
	httpP, httpsP := envVar("HTTP_PROXY", "http_proxy"), envVar("HTTPS_PROXY", "https_proxy")
	noP := envVar("NO_PROXY", "no_proxy")
	envState.mu.Lock()
	if key := httpP + "\x00" + httpsP; envState.fn == nil || envState.key != key {
		// NO_PROXY is read here by hand: the package's own rules never let a
		// loopback address through. A placeholder host stands in for it.
		cfg := &httpproxy.Config{HTTPProxy: httpP, HTTPSProxy: httpsP}
		envState.key, envState.fn = key, cfg.ProxyFunc()
	}
	fn := envState.fn
	envState.mu.Unlock()
	if noProxyMatches(noP, r.URL.Hostname(), r.URL.Port(), r.URL.Scheme) {
		return nil, nil
	}
	cp := *r.URL
	cp.Host = "loopback.azhaq.invalid"
	if p := r.URL.Port(); p != "" {
		cp.Host += ":" + p
	}
	return fn(&cp)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// noProxyMatches reads NO_PROXY as curl does: "*" for all, an address or
// CIDR range, a name or domain suffix (.example.com), each with an optional
// port.
func noProxyMatches(spec, host, port, scheme string) bool {
	if port == "" {
		port = map[string]string{"https": "443"}[scheme]
		if port == "" {
			port = "80"
		}
	}
	host = strings.ToLower(host)
	ip := net.ParseIP(host)
	for _, e := range strings.Split(spec, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if e == "*" {
			return true
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if ip != nil && n.Contains(ip) {
				return true
			}
			continue
		}
		name, p := e, ""
		if h, pp, err := net.SplitHostPort(e); err == nil {
			name, p = h, pp
		}
		name = strings.Trim(name, "[]")
		if p != "" && p != port {
			continue
		}
		if name == host || (strings.HasPrefix(name, ".") && strings.HasSuffix(host, name)) || (strings.HasPrefix(name, "*.") && strings.HasSuffix(host, name[1:])) {
			return true
		}
		if ip != nil {
			if eip := net.ParseIP(name); eip != nil && eip.Equal(ip) {
				return true
			}
		}
	}
	return false
}
