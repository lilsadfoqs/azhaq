package portscan

import (
	"slices"
	"testing"
)

// The first pass of the default scan asks the usual port of every service azhaq
// can name or check: of each protocol it identifies, plain and TLS, of each port
// it names a silent port by, and of each service a -verify check reads.
func TestDefaultPortsHoldThePortOfEveryServiceInTheCatalog(t *testing.T) {
	def := DefaultPorts()
	top, _ := Ports("top-1000")
	for _, p := range top {
		if !slices.Contains(def, p) {
			t.Errorf("the default set lacks %d, a port of the top 1000", p)
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
	for _, q := range []int{6379, 27017, 11211} {
		if !slices.Contains(def, q) {
			t.Errorf("the default set lacks %d", q)
		}
	}
	// The set is the top 1000 and the catalog, each port once, in order.
	want := map[int]bool{}
	for _, p := range top {
		want[p] = true
	}
	for _, p := range CatalogPorts() {
		want[p] = true
	}
	if len(def) != len(want) || !slices.IsSorted(def) || len(slices.Compact(slices.Clone(def))) != len(def) {
		t.Errorf("the default set has %d ports, the top 1000 and the catalog make %d", len(def), len(want))
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

// The usual set, which a scan with no ports asked before it had a second pass, is
// the top 100 and the catalog; only a list holding the name default goes on to a
// second pass.
func TestUsualPortsAndEscalation(t *testing.T) {
	top, _ := Ports("top-100")
	want := map[int]bool{}
	for _, p := range top {
		want[p] = true
	}
	for _, p := range CatalogPorts() {
		want[p] = true
	}
	if got := UsualPorts(); len(got) != len(want) || len(got) != 163 {
		t.Errorf("the usual set has %d ports, want %d (163)", len(got), len(want))
	}
	if got, want := len(DefaultPorts()), 1040; got != want {
		t.Errorf("the first pass has %d ports, want %d", got, want)
	}
	for spec, want := range map[string]bool{"": false, "default": true, " Default ": true, "top-100,default": true, "default,8888": true,
		"top-1000": false, "full": false, "22,80": false, "none": false} {
		if got := Escalates(spec); got != want {
			t.Errorf("Escalates(%q) = %v, want %v", spec, got, want)
		}
	}
}
