package portscan

import (
	"slices"
	"strings"
	"sync"
)

// DefaultName is the list name of the first pass of a scan that names no ports:
// DefaultPorts. A scan whose list holds it goes on to every TCP port of each
// address that answered the first pass (Escalates).
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

var usualPorts = sync.OnceValue(func() []int {
	top, _ := parseList(top100, top100, func(string) (string, bool) { return "", false }, "", nil)
	return union(top, CatalogPorts())
})

var defaultPorts = sync.OnceValue(func() []int {
	top, _ := parseList(top1000, top1000, func(string) (string, bool) { return "", false }, "", nil)
	return union(top, CatalogPorts())
})

func union(a, b []int) []int {
	set := map[int]bool{}
	for _, p := range a {
		set[p] = true
	}
	for _, p := range b {
		set[p] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// DefaultPorts is the first pass of the default scan: nmap's top 1000 TCP
// ports and the CatalogPorts the top 1000 leaves out (Redis, MongoDB and
// memcached among them).
func DefaultPorts() []int { return slices.Clone(defaultPorts()) }

// UsualPorts is the top 100 TCP ports and the CatalogPorts: the set a scan
// with no ports asked before the default had a second pass.
func UsualPorts() []int { return slices.Clone(usualPorts()) }

// Escalates says whether a scan of spec (a list as Ports reads it) goes on, past
// the first pass, to every TCP port of each address that answered it: when the
// list holds the name default.
func Escalates(spec string) bool {
	for _, w := range strings.Split(strings.ToLower(spec), ",") {
		if strings.TrimSpace(w) == DefaultName {
			return true
		}
	}
	return false
}
