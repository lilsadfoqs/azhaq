package normalize

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/lilsadfoqs/azhaq/types"
)

func Seed(s types.Seed) types.Seed {
	out := types.Seed{Type: s.Type, Keys: make(map[string]string, len(s.Keys))}
	for k, v := range s.Keys {
		out.Keys[k] = v
	}
	switch s.Type {
	case types.TypeURL:
		if u, err := URL(s.Keys["url"]); err == nil {
			out.Keys["url"] = u
		}
	case types.TypeHostname:
		out.Keys["fqdn"] = Hostname(s.Keys["fqdn"])
	case types.TypeDomain:
		out.Keys["domain"] = Hostname(s.Keys["domain"])
	}
	return out
}

var braces = strings.NewReplacer("%7B", "{", "%7D", "}")

func URL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errEmpty
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Fragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	host, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		if port == "" {
			return "", errPort // http://127.0.0.1:/x, the start of a URL a script builds at run time
		}
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			u.Host = host
		} else {
			u.Host = net.JoinHostPort(strings.ToLower(host), port)
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if p := u.EscapedPath(); strings.Contains(strings.ToLower(p), ";jsessionid") {
		p = dropSessionParam(p)
		if unesc, err := url.PathUnescape(p); err == nil {
			u.Path, u.RawPath = unesc, p
		}
	}
	// Keep {param} placeholders readable in API templates.
	out := braces.Replace(u.String())
	return out, nil
}

// dropSessionParam removes the servlet session path parameter
// (";jsessionid=...", named by the Servlet specification) from each segment
// of an escaped path: a server that rewrites its links with a fresh session
// id would otherwise make every page a new URL. Other path parameters stay.
func dropSessionParam(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		parts := strings.Split(seg, ";")
		keep := parts[:1]
		for _, x := range parts[1:] {
			name, _, _ := strings.Cut(x, "=")
			if !strings.EqualFold(name, "jsessionid") {
				keep = append(keep, x)
			}
		}
		segs[i] = strings.Join(keep, ";")
	}
	return strings.Join(segs, "/")
}

// ClientURL is URL for a view a single-page app's router draws: a hash
// route (#/administration, #!/admin) keeps its fragment, the only part
// that tells it from the app's front page. Any other fragment goes.
func ClientURL(raw string) (string, error) {
	base, frag, _ := strings.Cut(strings.TrimSpace(raw), "#")
	n, err := URL(base)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(frag, "/") || strings.HasPrefix(frag, "!/") {
		n += "#" + frag
	}
	return n, nil
}

func Hostname(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	return strings.TrimSuffix(h, ".")
}

// sharedPlatforms are multi-tenant suffixes. Two tenants are not one site.
var sharedPlatforms = []string{
	"appspot.com", "web.app", "firebaseapp.com", "herokuapp.com",
	"azurewebsites.net", "cloudfront.net", "github.io", "gitlab.io",
	"netlify.app", "vercel.app", "pages.dev", "workers.dev",
	"ngrok.io", "trycloudflare.com", "s3.amazonaws.com",
	"blob.core.windows.net", "googleusercontent.com", "googleapis.com",
	"cloudfunctions.net", "run.app",
}

// SharedSuffix is the platform name if host is on a shared PaaS.
func SharedSuffix(host string) string {
	host = Hostname(host)
	for _, s := range sharedPlatforms {
		if host == s || strings.HasSuffix(host, "."+s) {
			return s
		}
	}
	return ""
}

// Tenant says whether host lives under a name a provider hands out to
// its customers (a bucket on s3.amazonaws.com, an app on herokuapp.com):
// the provider's own domain is not the tenant's, and nothing under the
// tenant's name is worth enumerating or looking up in RDAP.
func Tenant(host string) bool {
	host = Hostname(host)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	if SharedSuffix(host) != "" {
		return true
	}
	// Private suffixes (github.io, s3.amazonaws.com) have several labels;
	// a TLD the list does not know has one, and is not a provider.
	suf, icann := publicsuffix.PublicSuffix(host)
	return !icann && strings.Contains(suf, ".")
}

// RegistrableDomain is eTLD+1, or empty for IPs and unknowns.
// Shared PaaS hosts stop at the tenant (a.appspot.com, not appspot.com).
func RegistrableDomain(host string) string {
	host = Hostname(host)
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if suf := SharedSuffix(host); suf != "" {
		if host == suf {
			return ""
		}
		rest := strings.TrimSuffix(host, "."+suf)
		if i := strings.LastIndex(rest, "."); i >= 0 {
			rest = rest[i+1:]
		}
		return rest + "." + suf
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return Hostname(d)
}

// SameSite is true when both names share a non-empty eTLD+1.
func SameSite(a, b string) bool {
	da, db := RegistrableDomain(a), RegistrableDomain(b)
	return da != "" && da == db
}

func HostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return Hostname(host)
}

// SpecialUse is true for RFC 2606 / 6761 names that cannot exist on the
// public internet (.test, .localhost, .invalid, .example, .local).
func SpecialUse(host string) bool {
	h := Hostname(host)
	if h == "" || net.ParseIP(h) != nil {
		return false
	}
	labels := strings.Split(h, ".")
	switch labels[len(labels)-1] {
	case "test", "example", "invalid", "localhost", "local":
		return true
	default:
		return false
	}
}

type emptyError struct{}

func (emptyError) Error() string { return "empty" }

var errEmpty emptyError

type portError struct{}

func (portError) Error() string { return "empty port" }

var errPort portError

// ReverseAddr is the address a full reverse name stands for.
func ReverseAddr(name string) (netip.Addr, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}
		var b [4]byte
		for i, l := range labels {
			var v int
			if _, err := fmt.Sscanf(l, "%d", &v); err != nil || v < 0 || v > 255 || fmt.Sprint(v) != l {
				return netip.Addr{}, false
			}
			b[3-i] = byte(v)
		}
		return netip.AddrFrom4(b), true
	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i, l := range labels {
			if len(l) != 1 || !strings.Contains("0123456789abcdef", l) {
				return netip.Addr{}, false
			}
			v := byte(strings.Index("0123456789abcdef", l))
			n := 31 - i
			if n%2 == 0 {
				b[n/2] |= v << 4
			} else {
				b[n/2] |= v
			}
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}
