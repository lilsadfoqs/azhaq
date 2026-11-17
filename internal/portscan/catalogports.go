package portscan

import (
	"fmt"
	"slices"
	"strconv"
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

// ServiceName is the service a catalog port is named by: the protocol azhaq
// asks first on it, else the registered name of the port. "" when it has none.
func ServiceName(port int) string {
	for _, p := range protocols {
		if slices.Contains(p.ports, port) || slices.Contains(p.tlsPorts, port) {
			return p.name
		}
	}
	return wellKnown[port]
}

// ServiceGap is the CatalogPorts that a scan of asked leaves out, less skip
// (the ports the user kept out): what -p default asks of them, and asked
// does not. It is derived from CatalogPorts, so it never drifts from default.
func ServiceGap(asked, skip []int) []int {
	have := make(map[int]bool, len(asked)+len(skip))
	for _, p := range asked {
		have[p] = true
	}
	for _, p := range skip {
		have[p] = true
	}
	var left []int
	for _, p := range CatalogPorts() {
		if !have[p] {
			left = append(left, p)
		}
	}
	return left
}

// NarrowName says whether spec (a list as Ports reads it) holds a named set
// narrower than default (top-100, top-1000) and no name that reaches it
// (default, full). An explicit list of ports is no named set.
func NarrowName(spec string) bool {
	narrow := false
	for _, w := range strings.Split(strings.ToLower(spec), ",") {
		switch strings.TrimSpace(w) {
		case DefaultName, "full", "all", "-":
			return false
		case "top-100", "top100", "top-1000", "top1000":
			narrow = true
		}
	}
	return narrow
}

// shownGap is how many ports of a gap a note names one by one.
const shownGap = 8

// GapList names the first few ports of a list by number and service,
// "853 dns-over-tls, 1883 mqtt, and 34 more".
func GapList(ports []int) string {
	var out []string
	for i, p := range ports {
		if i == shownGap {
			out = append(out, fmt.Sprintf("and %d more", len(ports)-i))
			break
		}
		if n := ServiceName(p); n != "" {
			out = append(out, fmt.Sprintf("%d %s", p, n))
		} else {
			out = append(out, strconv.Itoa(p))
		}
	}
	return strings.Join(out, ", ")
}

// AddsNote is what default adds to a scan that left ports of gap out, as
// flag (-p or -ports) names it: "-p default adds 40 service ports (853 dns, ...)".
func AddsNote(flag string, gap []int) string {
	n := "service ports"
	if len(gap) == 1 {
		n = "service port"
	}
	return fmt.Sprintf("%s default adds %d %s (%s)", flag, len(gap), n, GapList(gap))
}

// QuietNote says no port answered, and what -p default would add: of one
// address when addrs is 1, else of quiet of the addrs addresses asked. flag is
// the option that names the ports: -p of ports, -ports of run.
func QuietNote(flag string, asked, addrs, quiet int, gap []int) string {
	where := ""
	if addrs > 1 {
		where = fmt.Sprintf(" on %d of the %d addresses", quiet, addrs)
	}
	return fmt.Sprintf("no port answered among the %d asked%s; %s", asked, where, AddsNote(flag, gap))
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
