package portscan

import (
	"slices"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
	"github.com/lilsadfoqs/azhaq/internal/verify"
)

// A default scan asks the usual port of every service azhaq can name or
// check: of each protocol it identifies, plain and TLS, of each port it names
// a silent port by, and of each service a -verify check reads.
func TestDefaultPortsHoldThePortOfEveryServiceInTheCatalog(t *testing.T) {
	def := DefaultPorts()
	top, _ := Ports("top-100")
	for _, p := range top {
		if !slices.Contains(def, p) {
			t.Errorf("the default set lacks %d, a port of the top 100", p)
		}
	}
	n := 0
	for _, p := range protocols {
		for _, q := range append(slices.Clone(p.ports), p.tlsPorts...) {
			n++
			if !slices.Contains(def, q) {
				t.Errorf("the default set lacks %d, a usual port of %s", q, p.name)
			}
		}
	}
	for q, name := range wellKnown {
		n++
		if !slices.Contains(def, q) {
			t.Errorf("the default set lacks %d, which names %s", q, name)
		}
	}
	if n == 0 {
		t.Fatal("the catalog lists no port")
	}
	// The services the verification checks read, by the name the scan gives them.
	for _, c := range verify.Checks() {
		if _, ok := verify.ForService(advisory.Service{Service: c.Service}); !ok {
			t.Errorf("%s: no check for the service it names", c.ID)
		}
		p := protocolNamed(c.Service)
		if p == nil || len(p.ports) == 0 {
			t.Errorf("%s: the identification catalog has no usual port for %s", c.ID, c.Service)
			continue
		}
		for _, q := range p.ports {
			if !slices.Contains(def, q) {
				t.Errorf("the default set lacks %d, a port of %s, which -verify checks", q, c.Service)
			}
		}
	}
	for _, q := range []int{6379, 27017, 11211} {
		if !slices.Contains(def, q) {
			t.Errorf("the default set lacks %d", q)
		}
	}
	// The set is the top 100 and the catalog, each port once, in order.
	want := map[int]bool{}
	for _, p := range top {
		want[p] = true
	}
	for _, p := range CatalogPorts() {
		want[p] = true
	}
	if len(def) != len(want) || !slices.IsSorted(def) || len(slices.Compact(slices.Clone(def))) != len(def) {
		t.Errorf("the default set has %d ports, the top 100 and the catalog make %d", len(def), len(want))
	}
	if got, _ := Ports(""); !slices.Equal(got, def) {
		t.Errorf("an empty list is not the default set")
	}
	if got, _ := Ports("default"); !slices.Equal(got, def) {
		t.Errorf("the name default is not the default set")
	}
	if got, _ := Ports("default,8888"); len(got) < len(def) {
		t.Errorf("default,8888 has %d ports", len(got))
	}
	if _, err := UDPPorts("default"); err == nil {
		t.Errorf("UDP takes no list named default")
	}
}
