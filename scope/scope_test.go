package scope

import (
	"net/netip"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func TestAllowsSuffixAndDeny(t *testing.T) {
	r := Rules{Allow: []string{"example.test"}, Deny: []string{"evil.example.test"}}
	if !r.Allows("www.example.test") {
		t.Fatal("www should be allowed")
	}
	if r.Allows("evil.example.test") {
		t.Fatal("deny should win")
	}
	if r.Allows("other.test") {
		t.Fatal("other eTLD+1 should be out")
	}
	if !r.AllowsSeed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://app.example.test/"}}) {
		t.Fatal("in-scope URL")
	}
	if r.AllowsSeed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "https://nope.test/"}}) {
		t.Fatal("out-of-scope URL")
	}
}

func TestEmptyAllowsAll(t *testing.T) {
	var r Rules
	if !r.Allows("anywhere.test") {
		t.Fatal("empty rules allow all")
	}
}

func TestRuleForms(t *testing.T) {
	r := Rules{
		Allow: []string{"*.example.com", "=api.other.org", "10.1.0.0/16", "192.0.2.7"},
		Deny:  []string{"=admin.example.com", "10.1.9.0/24"},
	}
	for host, want := range map[string]bool{
		"example.com": true, "a.b.example.com": true, "admin.example.com": false,
		"api.other.org": true, "x.api.other.org": false, "other.org": false,
		"10.1.2.3": true, "10.1.9.9": false, "10.2.0.1": false,
		"192.0.2.7": true, "192.0.2.70": false,
	} {
		if got := r.Allows(host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
}

// A port copied into -allow/-deny (from a URL's authority) does not change
// which hosts are in scope (Allows); AllowsAddr is what holds a connection to
// the port. A bare IPv6 address keeps its colons.
func TestRulePortStripped(t *testing.T) {
	r := Rules{
		Allow: []string{"127.0.0.1:5013", "app.example.com:8443", "[2001:db8::1]:443"},
		Deny:  []string{"admin.example.com:8080"},
	}
	for host, want := range map[string]bool{
		"127.0.0.1":         true,
		"app.example.com":   true,
		"2001:db8::1":       true,
		"admin.example.com": false,
		"other.example.com": false,
	} {
		if got := r.Allows(host); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
	// A bare IPv6 in -allow (no port) still matches itself.
	if !(Rules{Allow: []string{"::1"}}).Allows("::1") {
		t.Error("bare IPv6 ::1 should match itself")
	}
}

func TestMatchNamesTheAllowRule(t *testing.T) {
	r := Rules{Allow: []string{"*.example.com", "=api.other.test", "10.0.0.0/8"}, Deny: []string{"dev.example.com"}}
	for host, want := range map[string]string{
		"www.example.com":   "*.example.com",
		"example.com":       "*.example.com",
		"api.other.test":    "=api.other.test",
		"www.other.test":    "",
		"10.1.2.3":          "10.0.0.0/8",
		"dev.example.com":   "",
		"x.dev.example.com": "",
		"evil.test":         "",
	} {
		if got := r.Match(host); got != want {
			t.Errorf("Match(%q) = %q, want %q", host, got, want)
		}
	}
	if got := (Rules{}).Match("a.test"); got != "" {
		t.Errorf("no rules: %q", got)
	}
}

// A compiled set of rules answers as the plain one does.
func TestCompileMatchesPlainRules(t *testing.T) {
	r := Rules{
		Allow: []string{"example.com", "*.wild.test", "=api.exact.org", "10.0.0.0/24", "192.0.2.7", "127.0.0.1:8080"},
		Deny:  []string{"admin.example.com", "10.0.0.9"},
	}
	c := r.Compile()
	for _, h := range []string{"example.com", "a.example.com", "admin.example.com", "x.admin.example.com", "wild.test", "q.wild.test",
		"api.exact.org", "x.api.exact.org", "exact.org", "10.0.0.5", "10.0.0.9", "10.0.1.5", "192.0.2.7", "192.0.2.8", "127.0.0.1", "other.net", "", "EXAMPLE.com."} {
		if r.Allows(h) != c.Allows(h) || r.Match(h) != c.Match(h) && c.Match(h) == "" != (r.Match(h) == "") {
			t.Errorf("%q: plain %v %q, compiled %v %q", h, r.Allows(h), r.Match(h), c.Allows(h), c.Match(h))
		}
	}
	if (Rules{}).Compile().Allows("anything") != true {
		t.Error("empty rules refuse")
	}
}

// A range is a target only where some address of it can pass: a domain
// rule never matches an address, an allow range must touch it, and a deny
// range holding it whole leaves nothing to ask.
func TestAllowsPrefix(t *testing.T) {
	for _, c := range []struct {
		rules Rules
		pf    string
		want  bool
	}{
		{Rules{}, "10.0.0.0/8", true},
		{Rules{Allow: []string{"127.0.0.1"}}, "127.0.0.2/32", false},
		{Rules{Allow: []string{"127.0.0.1"}}, "127.0.0.1/32", true},
		{Rules{Allow: []string{"127.0.0.1"}}, "127.0.0.0/30", true},
		{Rules{Allow: []string{"127.0.0.1"}}, "127.0.0.4/30", false},
		{Rules{Allow: []string{"10.1.0.0/16"}}, "10.0.0.0/8", true},    // the rule is inside the range
		{Rules{Allow: []string{"10.0.0.0/8"}}, "10.1.2.0/24", true},    // the range is inside the rule
		{Rules{Allow: []string{"10.1.0.0/16"}}, "10.2.0.0/24", false},  // neither
		{Rules{Allow: []string{"example.test"}}, "10.0.0.0/24", false}, // a name never allows an address
		{Rules{Deny: []string{"10.0.0.0/8"}}, "10.1.0.0/24", false},
		{Rules{Deny: []string{"10.1.0.0/24"}}, "10.0.0.0/8", true}, // a part denied, the rest asked
		{Rules{Deny: []string{"10.0.0.7"}}, "10.0.0.7/32", false},
		{Rules{Allow: []string{"2001:db8::/32"}}, "2001:db8:1::/120", true},
		{Rules{Allow: []string{"2001:db8::/32"}}, "2001:db9::/120", false},
		{Rules{Allow: []string{"10.0.0.0/8"}}, "2001:db8::/120", false},
	} {
		pf := netip.MustParsePrefix(c.pf)
		for _, compiled := range []bool{false, true} {
			r := c.rules
			if compiled {
				r = r.Compile()
			}
			if got := r.AllowsPrefix(pf); got != c.want {
				t.Errorf("%+v %s (compiled %v): %v, want %v", c.rules, c.pf, compiled, got, c.want)
			}
		}
	}
}

func TestHeaderOutside(t *testing.T) {
	r := Rules{Allow: []string{"127.0.0.1", "ok.lab"}, Deny: []string{"secret.lab"}}.Compile()
	for _, c := range []struct{ name, value, out string }{
		{"Host", "ok.lab", ""},
		{"host", "secret.lab:8080", "secret.lab"},
		{"X-Forwarded-Host", "ok.lab, other.test", "other.test"},
		{"x-original-host", "[::1]:80", "::1"},
		{"X-Host", "127.0.0.1:3001", ""},
		{"X-Forwarded-For", "other.test", ""},
	} {
		if got := r.HeaderOutside(c.name, c.value); got != c.out {
			t.Errorf("%s: %s: %q, want %q", c.name, c.value, got, c.out)
		}
	}
	if (Rules{}).HeaderOutside("Host", "anything.test") != "" {
		t.Error("no rules: nothing is outside")
	}
}

// A header that names a port is held to the entry's port as a URL is; one
// that names none is judged by the host.
func TestHeaderOutsidePort(t *testing.T) {
	r := Rules{Allow: []string{"127.0.0.1:3001", "any.test", "ports.test:80"}}.Compile()
	for _, c := range []struct{ name, value, out string }{
		{"Host", "127.0.0.1:3001", ""},
		{"Host", "127.0.0.1", ""},
		{"Host", "127.0.0.1:5002", "127.0.0.1"},
		{"x-forwarded-host", "any.test:8443", ""},
		{"X-Forwarded-Host", "127.0.0.1:3001, 127.0.0.1:5002", "127.0.0.1"},
		{"Host", "ports.test:80", ""},
		{"Host", "ports.test:81", "ports.test"},
		{"Host", "[::1]:3001", "::1"},
	} {
		if got := r.HeaderOutside(c.name, c.value); got != c.out {
			t.Errorf("%s: %s: %q, want %q", c.name, c.value, got, c.out)
		}
	}
}

// An allow entry with a port allows that host on that port only; one
// without allows every port. A deny entry keeps the host out on every port.
func TestAllowPortHoldsTheConnectionToThatPort(t *testing.T) {
	r := Rules{
		Allow: []string{"127.0.0.1:3001", "app.example.com:8443", "[2001:db8::1]:443", "open.example.com", "10.0.0.0/24", "=exact.test:81"},
		Deny:  []string{"admin.example.com:8080"},
	}
	for _, rr := range []Rules{r, r.Compile()} {
		for _, c := range []struct {
			host, port string
			want       bool
		}{
			{"127.0.0.1", "3001", true}, {"127.0.0.1", "3000", false}, {"127.0.0.1", "4200", false}, {"127.0.0.1", "03001", true},
			{"app.example.com", "8443", true}, {"app.example.com", "443", false}, {"x.app.example.com", "8443", true}, {"x.app.example.com", "80", false},
			{"2001:db8::1", "443", true}, {"2001:db8::1", "80", false},
			{"open.example.com", "1", true}, {"open.example.com", "65535", true}, {"a.open.example.com", "9090", true},
			{"10.0.0.7", "22", true}, {"10.0.1.7", "22", false},
			{"exact.test", "81", true}, {"exact.test", "80", false}, {"a.exact.test", "81", false},
			{"admin.example.com", "8080", false}, {"admin.example.com", "80", false},
			{"other.test", "80", false},
			{"127.0.0.1", "", true}, // no port to judge: the host alone
		} {
			if got := rr.AllowsAddr(c.host, c.port); got != c.want {
				t.Errorf("AllowsAddr(%q, %q) = %v, want %v", c.host, c.port, got, c.want)
			}
		}
		// The host alone is in scope wherever an entry names it: a lookup, a
		// subdomain, a seed.
		for _, h := range []string{"127.0.0.1", "app.example.com", "open.example.com", "exact.test"} {
			if !rr.Allows(h) {
				t.Errorf("Allows(%q) is false", h)
			}
		}
	}
	if !r.OnlyOtherPort("127.0.0.1", "3000") || r.OnlyOtherPort("127.0.0.1", "3001") || r.OnlyOtherPort("other.test", "3000") {
		t.Error("OnlyOtherPort names a host that is in scope on another port, and no other")
	}
}

// A URL's port is the one it names, else its scheme's.
func TestAllowsURLUsesThePortOfTheURL(t *testing.T) {
	r := Rules{Allow: []string{"127.0.0.1:3001", "web.test:443", "plain.test"}}.Compile()
	for raw, want := range map[string]bool{
		"http://127.0.0.1:3001/a": true, "http://127.0.0.1:3000/": false, "http://127.0.0.1/": false, "http://127.0.0.1:4200/x": false,
		"https://web.test/": true, "https://web.test:443/": true, "http://web.test/": false, "https://web.test:8443/": false,
		"http://plain.test:9/": true, "wss://web.test/socket": true, "ws://web.test/socket": false,
		"/relative": true, "not a url ://": true,
	} {
		if got := r.AllowsURL(raw); got != want {
			t.Errorf("AllowsURL(%q) = %v, want %v", raw, got, want)
		}
	}
	// A discovered URL is a seed: the port decides whether it is one.
	if r.AllowsSeed(types.Seed{Type: types.TypeURL, Keys: map[string]string{"url": "http://127.0.0.1:3000/"}}) {
		t.Error("a URL on another port is in scope as a seed")
	}
	if !r.AllowsSeed(types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "web.test"}}) {
		t.Error("a host named by an entry with a port is a seed")
	}
}
