package normalize

import (
	_ "embed"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// The IANA root zone database's list of delegated top-level domains
// (public domain), refreshed with scripts/tldgen. The public suffix list is
// not used for this: it lacks TLDs the root zone has (web, on 2026-11-16).
//
//go:embed tlds-alpha-by-domain.txt
var rootTLDFile string

var (
	rootOnce    sync.Once
	rootTLDs    map[string]bool
	rootVersion string // the list's header line, "Version 2026111600, Last Updated ..."
)

func loadRootTLDs() {
	rootTLDs = map[string]bool{}
	for _, l := range strings.Split(rootTLDFile, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "#"):
			if rootVersion == "" {
				rootVersion = strings.TrimSpace(strings.TrimPrefix(l, "#"))
			}
		default:
			rootTLDs[strings.ToLower(l)] = true
		}
	}
}

// RootListVersion is the embedded root-zone list's header: its version and
// the day IANA last updated it.
func RootListVersion() string {
	rootOnce.Do(loadRootTLDs)
	return rootVersion
}

// Delegated says the root zone delegates host's top-level domain, so a
// public resolver can answer for the name. A host with no TLD (a single
// label that is not one), an address or an empty name is not.
func Delegated(host string) bool {
	h := Hostname(host)
	if h == "" || net.ParseIP(h) != nil {
		return false
	}
	tld := h[strings.LastIndex(h, ".")+1:]
	if tld == "" {
		return false
	}
	if a, err := idna.Lookup.ToASCII(tld); err == nil {
		tld = a // a TLD written in Unicode is listed as xn--...
	}
	rootOnce.Do(loadRootTLDs)
	return rootTLDs[tld]
}

// Undelegated says host is in a zone no public service can hold names of:
// its top-level domain is not in the root zone (.internal, .lan, .corp,
// .intranet, and the special-use .test, .local, .invalid, ...), or it is
// under home.arpa (RFC 8375: delegated under arpa, but for home networks).
// Asking a public resolver, certificate-log search or archive about such a
// name only tells it the name. Reverse names (in-addr.arpa, ip6.arpa) are
// delegated and not counted here.
func Undelegated(host string) bool {
	h := Hostname(host)
	if h == "" || net.ParseIP(h) != nil {
		return false
	}
	return h == "home.arpa" || strings.HasSuffix(h, ".home.arpa") || !Delegated(h)
}
