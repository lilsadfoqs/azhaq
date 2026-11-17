package main

import (
	"fmt"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// portPace is the connect and datagram ceiling the port stage is given: what
// -port-rate says, bounded by -rate when both are given, and -rate alone when
// only it is: the user's ceiling is not held down to the default. 0 means
// neither was given, and the scan keeps its default with loopback unpaced.
func portPace(rate, portRate float64) float64 {
	switch {
	case rate > 0 && portRate > 0:
		return min(rate, portRate)
	case rate > 0:
		return rate
	}
	return portRate
}

// stagePaces says the pace of each stage of a run: the requests, the
// connects and datagrams of the port stage, and the DNS queries to the
// targets' own name servers. -rate bounds all of them together; -port-rate
// and -port-min-rate shape the port stage within it. With none of them the
// connects are paced adaptively (hostRate, when given, is the ceiling it does
// not rise over); the datagrams keep the start rate.
func stagePaces(rate, portRate, minRate, hostRate float64) map[string]string {
	text := func(r float64) string { return fmt.Sprintf("%g/s", r) }
	req, dns := "none", "none"
	if rate > 0 {
		req, dns = text(rate), text(rate)
	}
	port := portPace(rate, portRate)
	var conn, dgram string
	switch {
	case port > 0:
		if minRate > port {
			port = minRate
		}
		conn = text(port)
		if rate > 0 && port > rate {
			conn = text(rate) // -rate holds over -port-min-rate
		}
	case minRate > portscan.DefaultRate:
		conn = text(minRate)
	default:
		ceil := float64(portscan.AdaptiveCeiling)
		if hostRate > 0 {
			ceil = hostRate
		}
		ceil = max(ceil, portscan.DefaultRate)
		conn = fmt.Sprintf("adaptive from %s up to %s", text(portscan.DefaultRate), text(ceil))
		if minRate > 0 {
			conn += ", not under " + text(minRate)
		}
		conn += ", 127.0.0.1 unpaced"
		dgram = text(portscan.DefaultRate) + ", 127.0.0.1 unpaced"
	}
	if dgram == "" {
		dgram = conn
	}
	return map[string]string{"requests-pace": req, "connects-pace": conn, "datagrams-pace": dgram, "dns-pace": dns}
}

func paceLimits(l map[string]string, rate, portRate, minRate, hostRate float64) map[string]string {
	for k, v := range stagePaces(rate, portRate, minRate, hostRate) {
		l[k] = v
	}
	return l
}
