package scope

import (
	"net"
	"net/url"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
)

// TargetPorts is what a run with no rule holds the host of each URL target
// to: the ports the targets give it. A URL on its scheme's default port holds
// its host to 80 and 443, so a move from http to https stays in. A host a bare
// target covers (a name, an address, a domain or a range) keeps every port and
// is left out. Several URLs on one host allow each port.
func TargetPorts(urls, bare []string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := normalize.Hostname(u.Hostname())
		if host == "" || coveredBy(host, bare) {
			continue
		}
		if out[host] == nil {
			out[host] = map[string]bool{}
		}
		port := URLPort(u)
		if port == "" {
			continue
		}
		out[host][port] = true
		if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
			out[host]["80"], out[host]["443"] = true, true
		}
	}
	for h, ports := range out {
		if len(ports) == 0 {
			delete(out, h)
		}
	}
	return out
}

// coveredBy says a bare target names host: the same name, a name under a
// domain, or an address in a range.
func coveredBy(host string, bare []string) bool {
	ip := net.ParseIP(host)
	for _, b := range bare {
		b = strings.ToLower(strings.TrimSpace(b))
		switch {
		case b == host:
			return true
		case ip != nil:
			if _, n, err := net.ParseCIDR(b); err == nil && n.Contains(ip) {
				return true
			}
		case strings.HasSuffix(host, "."+b):
			return true
		}
	}
	return false
}
