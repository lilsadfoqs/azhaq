package scope

import (
	"net/netip"
	"testing"
)

// CountAddrs is what asking Allows of each address of the range says.
func TestCountAddrsMatchesAskingEachAddress(t *testing.T) {
	cases := []struct {
		name        string
		allow, deny []string
		pf          string
		want        uint64
	}{
		{"no rules", nil, nil, "10.0.0.0/24", 256},
		{"allow the range", []string{"10.0.0.0/24"}, nil, "10.0.0.0/24", 256},
		{"allow a wider range", []string{"10.0.0.0/8"}, nil, "10.0.0.0/24", 256},
		{"allow half", []string{"10.0.0.0/25"}, nil, "10.0.0.0/24", 128},
		{"allow other range", []string{"192.0.2.0/24"}, nil, "10.0.0.0/24", 0},
		{"allow a domain only", []string{"example.com"}, nil, "10.0.0.0/24", 0},
		{"allow addresses", []string{"10.0.0.1", "10.0.0.2", "10.0.0.2:80", "10.0.1.1"}, nil, "10.0.0.0/24", 2},
		{"deny a part", []string{"10.0.0.0/24"}, []string{"10.0.0.64/26"}, "10.0.0.0/24", 192},
		{"deny with no allow", nil, []string{"10.0.0.0/28", "10.0.0.5", "10.0.0.200"}, "10.0.0.0/24", 239},
		{"deny the whole", nil, []string{"10.0.0.0/16"}, "10.0.0.0/24", 0},
		{"overlapping allows", []string{"10.0.0.0/26", "10.0.0.32/27", "10.0.0.7"}, []string{"10.0.0.0/30"}, "10.0.0.0/24", 60},
		{"a single address", []string{"10.0.0.0/24"}, []string{"10.0.0.9"}, "10.0.0.9/32", 0},
		{"v6", []string{"2001:db8::/120"}, []string{"2001:db8::10/124"}, "2001:db8::/120", 240},
		{"v4 rule on a v6 range", []string{"10.0.0.0/8"}, nil, "2001:db8::/120", 0},
	}
	for _, c := range cases {
		for _, compiled := range []bool{false, true} {
			r := Rules{Allow: c.allow, Deny: c.deny}
			if compiled {
				r = r.Compile()
			}
			pf := netip.MustParsePrefix(c.pf)
			var brute uint64
			for a := pf.Addr(); pf.Contains(a); a = a.Next() {
				if r.Allows(a.String()) {
					brute++
				}
			}
			if got := r.CountAddrs(pf); got != c.want || brute != c.want {
				t.Errorf("%s (compiled %v): CountAddrs %d, asking each address %d, want %d", c.name, compiled, got, brute, c.want)
			}
		}
	}
}

// A range of millions of addresses is counted, not walked.
func TestCountAddrsOfAHugeRange(t *testing.T) {
	r := Rules{Allow: []string{"10.0.0.0/8"}, Deny: []string{"10.1.0.0/16"}}
	if got, want := r.CountAddrs(netip.MustParsePrefix("0.0.0.0/0")), uint64(1<<24-1<<16); got != want {
		t.Errorf("CountAddrs of /0 = %d, want %d", got, want)
	}
	if got := (Rules{}).CountAddrs(netip.MustParsePrefix("0.0.0.0/0")); got != 1<<32 {
		t.Errorf("no rules: %d", got)
	}
}

// The addresses an allow entry names with a port are the ones whose ports
// have to be asked.
func TestPortedAddrs(t *testing.T) {
	r := Rules{Allow: []string{"10.0.0.0/28", "10.0.0.5:8080", "10.0.1.9:80", "example.com:443"}, Deny: []string{"10.0.0.6"}}
	got := r.PortedAddrs(netip.MustParsePrefix("10.0.0.0/24"))
	if len(got) != 1 || got[0].String() != "10.0.0.5" {
		t.Errorf("PortedAddrs = %v, want 10.0.0.5", got)
	}
	if !r.HasPortRules() || (Rules{Allow: []string{"10.0.0.0/28"}}).HasPortRules() {
		t.Errorf("HasPortRules is wrong")
	}
}
