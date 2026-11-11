package main

import (
	"net/netip"
	"net/url"
	"strconv"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/types"
)

// A run that names no -ports and has a range or an address (a bare one: no scheme, no port) among its targets
// scans -ports default: the first pass of every address, then every TCP port of
// each address that answered it. A name, a URL or an AS number alone does not
// start a scan of ports.

// hasAddressTarget says whether a range or an address is among the targets.
func hasAddressTarget(seeds []types.Seed) bool {
	for _, s := range seeds {
		switch s.Type {
		case types.TypePrefix:
			return true
		case types.TypeIPAddress, types.TypeHostname:
			if _, err := netip.ParseAddr(normalize.Hostname(s.Key())); err == nil {
				return true
			}
		case types.TypeURL:
			// A bare address (no scheme, no port) is an address; a URL is not.
			if u, err := url.Parse(s.Key()); err == nil && s.Keys[types.BareKey] != "" {
				if _, err := netip.ParseAddr(u.Hostname()); err == nil {
					return true
				}
			}
		}
	}
	return false
}

// defaultedPorts is the -ports a run is given: the one it was, or default when it
// named none (nor UDP ports, which ask no TCP port), is not passive, and has a
// range or an address among its targets.
func defaultedPorts(spec, udp string, passive bool, seeds []types.Seed) string {
	if spec != "" || udp != "" || passive || !hasAddressTarget(seeds) {
		return spec
	}
	return portscan.DefaultName
}

// urlPortsOn are, by address, the ports of the URL targets that name an address
// with a port: an HTTP answer there makes the address one that answered, so the
// first pass asks that port too.
func urlPortsOn(seeds []types.Seed) map[string][]int {
	out := map[string][]int{}
	for _, s := range seeds {
		if s.Type != types.TypeURL {
			continue
		}
		u, err := url.Parse(s.Key())
		if err != nil {
			continue
		}
		a, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			continue
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
			host := a.Unmap().String()
			out[host] = append(out[host], n)
		}
	}
	return out
}
