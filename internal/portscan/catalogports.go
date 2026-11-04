package portscan

import (
	"slices"
	"sync"
)

// DefaultName is the list name of the ports a scan asks when none are named.
const DefaultName = "default"

// CatalogPorts are the usual TCP ports of the services azhaq can name from
// what a port says or answers: of each protocol it identifies (the port its
// own request goes to first, and the port of its TLS-wrapped variant), and the
// ports it names a silent port by. The verification checks (verify.Checks) are
// of services among them, so the ports of the services it can check are here.
// A protocol with no fixed port (one read only from a greeting on any port)
// has none to give. It is derived from those lists, so that a protocol added
// to them is scanned by default with no edit here.
func CatalogPorts() []int {
	set := map[int]bool{}
	for _, p := range protocols {
		for _, q := range p.ports {
			set[q] = true
		}
		for _, q := range p.tlsPorts {
			set[q] = true
		}
	}
	for q := range wellKnown {
		set[q] = true
	}
	out := make([]int, 0, len(set))
	for q := range set {
		out = append(out, q)
	}
	slices.Sort(out)
	return out
}

var defaultPorts = sync.OnceValue(func() []int {
	top, _ := parseList(top100, top100, func(string) (string, bool) { return "", false }, "", nil)
	set := map[int]bool{}
	for _, p := range top {
		set[p] = true
	}
	for _, p := range CatalogPorts() {
		set[p] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
})

// DefaultPorts is the set a scan asks when no ports are named: the top 100 TCP
// ports and the CatalogPorts, the services azhaq can name and check, which the
// top 100 leaves out (Redis, MongoDB and memcached among them).
func DefaultPorts() []int { return slices.Clone(defaultPorts()) }
