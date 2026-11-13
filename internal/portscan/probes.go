package portscan

import "slices"

// Probe is the one request a client with no credentials sends to read what a
// protocol's service states about itself, and how its answer is read. It is
// the request the identification sends to a port that waits, so a check
// built on it asks nothing the scan does not already ask.
type Probe struct {
	// Request is the bytes written to the connection.
	Request []byte
	// Read says what an answer states; false when it is not the protocol's.
	Read func(answer []byte) (ProbeAnswer, bool)
}

// ProbeAnswer is what the service stated. VersionRange is what its answer
// allows, not a version (see Open).
type ProbeAnswer struct {
	Product, Version, Banner   string
	VersionRange, VersionBasis string
}

// ProbeFor is the Probe of the protocol named name, for a service on host:port
// (some requests name the host). A protocol read only from a greeting, which
// has no request, has none.
func ProbeFor(name, host string, port int) (Probe, bool) {
	p := protocolNamed(name)
	if p == nil || p.request == nil {
		return Probe{}, false
	}
	pr := Probe{Request: p.request(target{host: host, port: port})}
	read := p.read
	if name == "dns" {
		// The scan's own second question on the same connection: the
		// version the server states, which the first one does not.
		q := versionBindQuery()
		pr.Request = dnsTCP(q)
		pr.Read = func(a []byte) (ProbeAnswer, bool) {
			if len(a) > 2 {
				if prod, v, ok := versionBind(a[2:], q); ok {
					return ProbeAnswer{Product: prod, Version: v, Banner: "version.bind"}, true
				}
			}
			return ProbeAnswer{}, false
		}
		return pr, true
	}
	pr.Read = func(a []byte) (ProbeAnswer, bool) {
		var o Open
		if !read(a, &o) {
			return ProbeAnswer{}, false
		}
		return ProbeAnswer{Product: o.Product, Version: o.Version, VersionRange: o.VersionRange, VersionBasis: o.VersionBasis, Banner: o.Banner}, true
	}
	return pr, true
}

// identifiedByGreeting are the services named from what a port says first,
// with no request of azhaq's own. They are not in the protocol list: the
// banner patterns (names.go) and the greeting signatures name them.
var identifiedByGreeting = []string{"ssh", "ftp", "smtp", "pop3", "imap", "mysql", "icy", "ftp-or-smtp"}

// identifiedByWeb are the names a port gets from an HTTP answer or a TLS
// handshake, and from a close with no word.
var identifiedByWeb = []string{"http", "https", "tls", "tcpwrapped"}

// IdentifiedServices lists every TCP service name a scan can give an open
// port from what it answers, sorted and with no name twice: the protocols
// with their own reader, the greetings and the web and TLS names. A name that
// only guesses by port number (a name with a question mark) is not one.
func IdentifiedServices() []string {
	var out []string
	for _, p := range protocols {
		out = append(out, p.name)
	}
	out = append(out, identifiedByGreeting...)
	out = append(out, identifiedByWeb...)
	slices.Sort(out)
	return slices.Compact(out)
}

// ProtocolPorts are the usual TCP ports of the protocol named name, plain
// and TLS-wrapped.
func ProtocolPorts(name string) []int {
	p := protocolNamed(name)
	if p == nil {
		return nil
	}
	return append(slices.Clone(p.ports), p.tlsPorts...)
}
