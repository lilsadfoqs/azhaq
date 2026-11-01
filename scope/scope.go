// Package scope decides which hosts a run may expand to (-allow, -deny).
package scope

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// Rules is an optional allow/deny list for active fan-out (hosts and URLs).
// Empty Allow means any host is allowed unless it matches Deny. An entry is
//
//	example.com      the domain and its subdomains
//	*.example.com    the same (bug bounty scopes write wildcards this way)
//	=api.example.com that host only
//	10.0.0.0/8       addresses in the range; 192.0.2.7 is one address
//	127.0.0.1:3001   that host on that port only (an entry without a port
//	                 allows every port); also app.example.com:8443, [::1]:80
//
// A port belongs to an allow entry alone: Allows(host) is true for a host any
// entry names, and AllowsAddr(host, port) holds a connection to the entry's
// port. A deny entry keeps its host out on every port, whatever port it names.
//
// DenyPath holds the user's own rules for paths (-deny-path): a regular
// expression matched against a URL's path, and against path and query
// together. A URL it matches is never requested. azhaq adds none itself.
type Rules struct {
	Allow    []string
	Deny     []string
	DenyPath []string

	idx *index // from Compile: lookups that do not read every rule
}

// CompilePaths checks the -deny-path expressions, so a bad one is a usage
// error before any request goes out.
func CompilePaths(patterns []string) error {
	for _, p := range patterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("-deny-path %q is not a regular expression: %v", p, err)
		}
	}
	return nil
}

// DeniedPath is the -deny-path rule that keeps raw out, as it was written,
// or "" when none does. It reads the path as sent and decoded, with and
// without the query, so an escaped dot or slash does not step round a rule.
func (r Rules) DeniedPath(raw string) string {
	if len(r.DenyPath) == 0 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	forms := []string{u.Path}
	if e := u.EscapedPath(); e != u.Path {
		forms = append(forms, e)
	}
	if u.RawQuery != "" {
		for _, f := range forms[:len(forms):len(forms)] {
			forms = append(forms, f+"?"+u.RawQuery)
		}
	}
	paths := r.paths()
	for i, re := range paths {
		if re == nil {
			continue
		}
		for _, f := range forms {
			if re.MatchString(f) {
				return r.DenyPath[i]
			}
		}
	}
	return ""
}

// paths are the compiled -deny-path expressions, nil where one does not compile.
func (r Rules) paths() []*regexp.Regexp {
	if r.idx != nil && len(r.idx.paths) == len(r.DenyPath) {
		return r.idx.paths
	}
	return compilePaths(r.DenyPath)
}

func compilePaths(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i], _ = regexp.Compile(p)
	}
	return out
}

func (r Rules) Empty() bool {
	return len(r.Allow) == 0 && len(r.Deny) == 0
}

func (r Rules) Allows(host string) bool {
	host = normalize.Hostname(host)
	if host == "" {
		return true
	}
	if r.idx != nil {
		if r.idx.deny.match(host) {
			return false
		}
		return len(r.Allow) == 0 || r.idx.allow.match(host)
	}
	for _, d := range r.Deny {
		if hostMatch(host, d) {
			return false
		}
	}
	if len(r.Allow) == 0 {
		return true
	}
	for _, a := range r.Allow {
		if hostMatch(host, a) {
			return true
		}
	}
	return false
}

// AllowsAddr says whether a connection to host on port may be made: the host
// is allowed, and the allow entry that names it either has no port or has
// this one. A port "" is unknown: the host alone is judged.
func (r Rules) AllowsAddr(host, port string) bool {
	host = normalize.Hostname(host)
	port = normPort(port)
	if host == "" || port == "" {
		return r.Allows(host)
	}
	if r.idx != nil {
		if r.idx.deny.match(host) {
			return false
		}
		return len(r.Allow) == 0 || r.idx.allow.matchPort(host, port)
	}
	for _, d := range r.Deny {
		if hostMatch(host, d) {
			return false
		}
	}
	if len(r.Allow) == 0 {
		return true
	}
	for _, a := range r.Allow {
		if hostMatchPort(host, a, port) {
			return true
		}
	}
	return false
}

// OnlyOtherPort says host is allowed, and only on ports other than port: the
// reason a connection AllowsAddr refuses is the port, not the host.
func (r Rules) OnlyOtherPort(host, port string) bool {
	return normPort(port) != "" && r.Allows(host) && !r.AllowsAddr(host, port)
}

// AllowsURL says whether a request to raw may be made: AllowsAddr for its
// host and its port, the scheme's when it names none (80, 443). A URL that
// does not parse, or names no host, is judged by what it has.
func (r Rules) AllowsURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return true
	}
	return r.AllowsAddr(u.Hostname(), URLPort(u))
}

// URLPort is the port a request to u goes to: the one it names, else its
// scheme's; "" for a scheme with none.
func URLPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	}
	return ""
}

// Match is the allow rule that lets host through, as it was written, or ""
// when none does: no rules, a host a deny rule excludes, or a host outside
// the allow list.
func (r Rules) Match(host string) string {
	host = normalize.Hostname(host)
	if host == "" || len(r.Allow) == 0 {
		return ""
	}
	if r.idx != nil && !r.idx.allow.match(host) {
		return ""
	}
	for _, d := range r.Deny {
		if hostMatch(host, d) {
			return ""
		}
	}
	for _, a := range r.Allow {
		if hostMatch(host, a) {
			return a
		}
	}
	return ""
}

func (r Rules) AllowsSeed(s types.Seed) bool {
	if r.Empty() {
		return true
	}
	s = normalize.Seed(s)
	switch s.Type {
	case types.TypeURL:
		return r.AllowsURL(s.Key())
	case types.TypeHostname, types.TypeDomain, types.TypeIPAddress:
		return r.Allows(s.Key())
	default:
		return true
	}
}

// AllowsPrefix says whether any address of pf can pass the rules. A range
// no allow rule touches (a domain never matches an address) or one a deny
// range holds whole has no address to ask, and is not a target.
func (r Rules) AllowsPrefix(pf netip.Prefix) bool {
	pf = pf.Masked()
	if r.Empty() {
		return true
	}
	if pf.IsSingleIP() {
		return r.Allows(pf.Addr().String())
	}
	idx := r.idx
	if idx == nil {
		idx = &index{allow: compileSet(r.Allow), deny: compileSet(r.Deny)}
	}
	for _, n := range idx.deny.nets {
		if o, _ := n.Mask.Size(); n.Contains(pf.Addr().AsSlice()) && o <= pf.Bits() && len(n.IP) == pf.Addr().BitLen()/8 {
			return false
		}
	}
	if len(r.Allow) == 0 {
		return true
	}
	for _, n := range idx.allow.nets {
		if n.Contains(pf.Addr().AsSlice()) {
			return true
		}
		if a, ok := netip.AddrFromSlice(n.IP); ok && pf.Contains(a.Unmap()) {
			return true
		}
	}
	// Addresses written out: the smaller of the range and the rules is walked.
	if size := uint64(1) << min(32, pf.Addr().BitLen()-pf.Bits()); size <= uint64(len(idx.allow.exact)) {
		for a := pf.Addr(); pf.Contains(a); a = a.Next() {
			if idx.allow.exact[a.String()] {
				return true
			}
		}
		return false
	}
	for host := range idx.allow.exact {
		if a, err := netip.ParseAddr(host); err == nil && pf.Contains(a) {
			return true
		}
	}
	return false
}

func hostMatch(host, rule string) bool { return hostMatchPort(host, rule, "") }

// ruleHost splits an allow or deny entry written as a host with a port
// (127.0.0.1:5013, [::1]:80): the entry without it, and the port. Only a
// real host:port is split; a bare IPv6 address (::1) and a bare host are left
// as they are. A range has no port.
func ruleHost(rule string) (host, port string) {
	rule = strings.TrimSpace(rule)
	if strings.Contains(rule, "/") {
		return rule, ""
	}
	exact := strings.HasPrefix(rule, "=")
	rest := strings.TrimPrefix(strings.TrimPrefix(rule, "="), "*.")
	if h, p, err := net.SplitHostPort(rest); err == nil && allDigits(p) {
		rest, port = h, normPort(p)
	}
	if exact {
		rest = "=" + rest
	}
	return rest, port
}

// normPort is a port as a number without leading zeros, "" for none.
func normPort(p string) string {
	if p == "" || !allDigits(p) {
		return ""
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return ""
	}
	return strconv.Itoa(n)
}

// hostMatchPort is hostMatch that, with a port, also holds an entry that
// names a port to it; a port "" asks about the host alone.
func hostMatchPort(host, rule, port string) bool {
	rule = strings.TrimSpace(rule)
	if strings.Contains(rule, "/") {
		_, n, err := net.ParseCIDR(rule)
		ip := net.ParseIP(host)
		return err == nil && ip != nil && n.Contains(ip)
	}
	rule, rport := ruleHost(rule)
	if rport != "" && port != "" && rport != port {
		return false
	}
	exact := strings.HasPrefix(rule, "=")
	rule = strings.TrimPrefix(rule, "=")
	rule = normalize.Hostname(rule)
	if rule == "" {
		return false
	}
	if host == rule {
		return true
	}
	if exact || net.ParseIP(rule) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+rule)
}

// allDigits is true for a non-empty string of ASCII digits (a port number).
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Compile is r with its rules indexed: a run over tens of thousands of
// targets, each one an allow rule, asks about each host in constant time
// instead of reading every rule. Rules built by hand work as before.
func (r Rules) Compile() Rules {
	r.idx = &index{allow: compileSet(r.Allow), deny: compileSet(r.Deny), paths: compilePaths(r.DenyPath)}
	return r
}

type index struct {
	allow, deny ruleSet
	paths       []*regexp.Regexp
}

// ruleSet holds rules by kind, to answer hostMatch for a host without
// reading them all.
type ruleSet struct {
	exact  map[string]bool // a host or address, as written
	suffix map[string]bool // a domain: it and everything under it
	nets   []*net.IPNet
	// The same rules by the ports they allow, for a connection: bare are
	// those written without a port, every port; onPort are those that name
	// one, by host and then port.
	bareExact, bareSuffix   map[string]bool
	exactPorts, suffixPorts map[string]map[string]bool
}

func compileSet(rules []string) ruleSet {
	set := ruleSet{exact: map[string]bool{}, suffix: map[string]bool{}, bareExact: map[string]bool{}, bareSuffix: map[string]bool{},
		exactPorts: map[string]map[string]bool{}, suffixPorts: map[string]map[string]bool{}}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if strings.Contains(rule, "/") {
			if _, n, err := net.ParseCIDR(rule); err == nil {
				set.nets = append(set.nets, n)
			}
			continue
		}
		rule, port := ruleHost(rule)
		exact := strings.HasPrefix(rule, "=")
		rule = normalize.Hostname(strings.TrimPrefix(rule, "="))
		if rule == "" {
			continue
		}
		suffix := !exact && net.ParseIP(rule) == nil
		set.exact[rule] = true
		if suffix {
			set.suffix[rule] = true
		}
		if port == "" {
			set.bareExact[rule] = true
			if suffix {
				set.bareSuffix[rule] = true
			}
			continue
		}
		addPort(set.exactPorts, rule, port)
		if suffix {
			addPort(set.suffixPorts, rule, port)
		}
	}
	return set
}

func addPort(m map[string]map[string]bool, host, port string) {
	if m[host] == nil {
		m[host] = map[string]bool{}
	}
	m[host][port] = true
}

func (s ruleSet) match(host string) bool {
	if s.exact[host] {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && s.suffix[host[i+1:]] {
			return true
		}
	}
	return s.inNets(host)
}

func (s ruleSet) inNets(host string) bool {
	if len(s.nets) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range s.nets {
				if n.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// matchPort is match for a connection to port: a rule that names a port
// holds it to that one.
func (s ruleSet) matchPort(host, port string) bool {
	if s.bareExact[host] || s.exactPorts[host][port] {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && (s.bareSuffix[host[i+1:]] || s.suffixPorts[host[i+1:]][port]) {
			return true
		}
	}
	return s.inNets(host)
}

// HostHeaders are the request headers that name the host a front end
// serves (a CDN or an ingress routes by them).
var HostHeaders = []string{"Host", "X-Forwarded-Host", "X-Host", "X-Original-Host"}

// NamesHost says whether a header of this name names a host, in any case.
func NamesHost(name string) bool {
	name = strings.TrimSpace(name)
	for _, h := range HostHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// HeaderHosts are the hosts the value of a host-naming header names: a list
// (X-Forwarded-Host: a.test, b.test) names each, and a port is dropped.
func HeaderHosts(value string) []string {
	var out []string
	for _, a := range HeaderAddrs(value) {
		out = append(out, a[0])
	}
	return out
}

// HeaderAddrs are the host and the port ("" when none is named) of each
// address the value of a host-naming header names.
func HeaderAddrs(value string) [][2]string {
	var out [][2]string
	for _, v := range strings.Split(value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		port := ""
		if h, p, err := net.SplitHostPort(v); err == nil {
			v, port = h, normPort(p)
		}
		out = append(out, [2]string{strings.Trim(v, "[]"), port})
	}
	return out
}

// HeaderOutside is the first host a host-naming header names that the rules
// leave out, "" when every one is in. A header that is not host-naming
// names none.
func (r Rules) HeaderOutside(name, value string) string {
	if r.Empty() {
		return ""
	}
	return HeaderOutsideBy(r.AllowsAddr, name, value)
}

// HeaderOutsideBy is HeaderOutside for any test of a host and port (a port
// "" asks about the host alone): the one place a header that names a host is
// held to a scope. A port the header names is held to an -allow entry's port
// as a URL's is.
func HeaderOutsideBy(allows func(host, port string) bool, name, value string) string {
	if allows == nil || !NamesHost(name) {
		return ""
	}
	for _, a := range HeaderAddrs(value) {
		if !allows(a[0], a[1]) {
			return a[0]
		}
	}
	return ""
}
