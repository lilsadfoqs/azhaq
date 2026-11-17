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
// to them is scanned by default with no edit here. The products of the login
// and read catalogs (verify) add their documented ports by
// RegisterServicePorts, and productPorts holds a few named by detection
// templates, which carry no port of their own.
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
	svcMu.Lock()
	for q := range svcPorts {
		set[q] = true
	}
	svcMu.Unlock()
	for _, pp := range productPorts {
		for _, q := range pp.ports {
			set[q] = true
		}
	}
	out := make([]int, 0, len(set))
	for q := range set {
		out = append(out, q)
	}
	slices.Sort(out)
	return out
}

// svcPorts are the ports products register: port -> product names. The caches
// below are dropped when it grows, so a late registration is never missed.
var (
	svcMu      sync.Mutex
	svcPorts   = map[int][]string{}
	usualCache []int
	defCache   []int
)

// RegisterServicePorts adds the documented ports of product to the catalog
// ports, and so to default. verify calls it for each entry of its login and
// read catalogs, so the port a check needs is read from the entry itself.
// (portscan cannot read verify: verify imports portscan.)
func RegisterServicePorts(product string, ports ...int) {
	name := strings.ToLower(product)
	svcMu.Lock()
	defer svcMu.Unlock()
	for _, p := range ports {
		if !slices.Contains(svcPorts[p], name) {
			svcPorts[p] = append(svcPorts[p], name)
		}
	}
	usualCache, defCache = nil, nil
}

// productPorts are the default ports of products azhaq names (a detection
// template ships for each; templates hold no port, so they are listed here),
// with the page that states each.
var productPorts = []struct {
	product string
	ports   []int
}{
	{"kibana", []int{5601}},    // https://www.elastic.co/guide/en/kibana/current/settings.html (server.port)
	{"couchdb", []int{5984}},   // https://docs.couchdb.org/en/stable/config/http.html ([chttpd] port)
	{"solr", []int{8983}},      // https://solr.apache.org/guide/solr/latest/deployment-guide/solr-control-script-reference.html (-p)
	{"nacos", []int{8848}},     // https://nacos.io/en/docs/v2/quickstart/quick-start/ (server on 127.0.0.1:8848)
	{"zipkin", []int{9411}},    // https://zipkin.io/pages/quickstart.html
	{"couchbase", []int{8091}}, // https://docs.couchbase.com/server/current/install/install-ports.html (web console)
	{"portainer", []int{9443}}, // https://docs.portainer.io/start/install-ce/server/docker/linux (UI)
}

func usualSet() []int {
	svcMu.Lock()
	c := usualCache
	svcMu.Unlock()
	if c != nil {
		return c
	}
	top, _ := parseList(top100, top100, func(string) (string, bool) { return "", false }, "", nil)
	c = union(top, CatalogPorts())
	svcMu.Lock()
	usualCache = c
	svcMu.Unlock()
	return c
}

func defaultSet() []int {
	svcMu.Lock()
	c := defCache
	svcMu.Unlock()
	if c != nil {
		return c
	}
	top, _ := parseList(top1000, top1000, func(string) (string, bool) { return "", false }, "", nil)
	c = union(top, CatalogPorts())
	svcMu.Lock()
	defCache = c
	svcMu.Unlock()
	return c
}

// productNames is the products that give port a name, "a/b" when several do.
func productNames(port int) string {
	var names []string
	svcMu.Lock()
	names = append(names, svcPorts[port]...)
	svcMu.Unlock()
	for _, pp := range productPorts {
		if slices.Contains(pp.ports, port) && !slices.Contains(names, pp.product) {
			names = append(names, pp.product)
		}
	}
	slices.Sort(names)
	return strings.Join(names, "/")
}

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
// asks first on it, else the registered name of the port, else the product
// whose documented port it is. "" when it has none.
func ServiceName(port int) string {
	for _, p := range protocols {
		if slices.Contains(p.ports, port) || slices.Contains(p.tlsPorts, port) {
			return p.name
		}
	}
	if n, ok := wellKnown[port]; ok {
		return n
	}
	return productNames(port)
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
// ports and the CatalogPorts the top 1000 leaves out (Redis, MongoDB,
// memcached and the console ports of the products verify checks among them).
func DefaultPorts() []int { return slices.Clone(defaultSet()) }

// UsualPorts is the top 100 TCP ports and the CatalogPorts: the set a scan
// with no ports asked before the default had a second pass.
func UsualPorts() []int { return slices.Clone(usualSet()) }

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
