package takeover

import "testing"

// A CNAME chain that ends at a name that answered NXDOMAIN is dangling
// whatever the target is: a provider's name or any other. The owner's own
// name, a target that resolved, and no chain are not.
func TestMeasureDangling(t *testing.T) {
	d, ok := Measure("old.example.com", []string{"a.cdn.example.net", "x.cloudprovider.example"}, true, "1.1.1.1")
	if !ok || d.Target != "x.cloudprovider.example" || d.Rcode != "NXDOMAIN" || d.Server != "1.1.1.1" || len(d.Chain) != 2 {
		t.Fatalf("%+v %v", d, ok)
	}
	if _, ok := Measure("a.example.com", []string{"gone.azurewebsites.net"}, true, ""); !ok {
		t.Error("a name on a provider's list is dangling too")
	}
	for name, c := range map[string]struct {
		host  string
		chain []string
		gone  bool
	}{
		"own name":   {"a.example.com", []string{"missing.example.com"}, true},
		"resolves":   {"a.example.com", []string{"x.example.net"}, false},
		"no chain":   {"a.example.com", nil, true},
		"own parent": {"a.b.example.co.uk", []string{"gone.example.co.uk"}, true},
	} {
		if _, ok := Measure(c.host, c.chain, c.gone, ""); ok {
			t.Errorf("%s is not dangling", name)
		}
	}
}
