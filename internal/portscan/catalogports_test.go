package portscan

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A product that productPorts names has a detection template azhaq ships:
// azhaq names it, so its port belongs to default. The templates carry no port.
func TestProductPortsAreOfProductsWithATemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "detect", "templates.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Units []struct {
			P string `json:"p"`
		} `json:"units"`
	}
	if err := json.NewDecoder(zr).Decode(&data); err != nil {
		t.Fatal(err)
	}
	for _, pp := range productPorts {
		found := false
		for _, u := range data.Units {
			if strings.Contains(strings.ToLower(u.P), pp.product) {
				found = true
				break
			}
		}
		if !found || len(pp.ports) == 0 {
			t.Errorf("%s: template found %v, ports %v", pp.product, found, pp.ports)
		}
	}
}

// Registering a product's ports adds them to default and names them, once.
func TestRegisterServicePortsReachesDefault(t *testing.T) {
	const port = 60999
	if slices.Contains(DefaultPorts(), port) {
		t.Fatalf("%d is in default already", port)
	}
	t.Cleanup(func() {
		svcMu.Lock()
		delete(svcPorts, port)
		usualCache, defCache = nil, nil
		svcMu.Unlock()
	})
	RegisterServicePorts("Acme Broker", port)
	RegisterServicePorts("acme broker", port)
	if !slices.Contains(DefaultPorts(), port) || !slices.Contains(UsualPorts(), port) {
		t.Errorf("%d is not in default after the registration", port)
	}
	if got := ServiceName(port); got != "acme broker" {
		t.Errorf("name %q", got)
	}
}

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
	for _, pp := range productPorts {
		for _, q := range pp.ports {
			n++
			if !slices.Contains(def, q) {
				t.Errorf("the default set lacks %d, a port of %s", q, pp.product)
			}
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
	if got := UsualPorts(); len(got) != len(want) {
		t.Errorf("the usual set has %d ports, want %d", len(got), len(want))
	}
	for spec, want := range map[string]bool{"": false, "default": true, " Default ": true, "top-100,default": true, "default,8888": true,
		"top-1000": false, "full": false, "22,80": false, "none": false} {
		if got := Escalates(spec); got != want {
			t.Errorf("Escalates(%q) = %v, want %v", spec, got, want)
		}
	}
}
