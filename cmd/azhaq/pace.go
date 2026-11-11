package main

import (
	"fmt"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
)

// portPace is the connect and datagram ceiling the port stage is given: what
// -port-rate says, bounded by -rate when both are given, and -rate alone (up
// to the scan's default) when only it is. 0 means neither was given, and the
// scan keeps its default with loopback unpaced.
func portPace(rate, portRate float64) float64 {
	switch {
	case rate > 0 && portRate > 0:
		return min(rate, portRate)
	case rate > 0:
		return min(rate, portscan.DefaultRate)
	}
	return portRate
}

// stagePaces says the pace of each stage of a run: the requests, the
// connects and datagrams of the port stage, and the DNS queries to the
// targets' own name servers. -rate bounds all of them together; -port-rate
// and -port-min-rate shape the port stage within it.
func stagePaces(rate, portRate, minRate float64) map[string]string {
	text := func(r float64) string { return fmt.Sprintf("%g/s", r) }
	req, dns := "none", "none"
	if rate > 0 {
		req, dns = text(rate), text(rate)
	}
	port := portPace(rate, portRate)
	var conn string
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
		conn = text(portscan.DefaultRate) + ", 127.0.0.1 unpaced"
	}
	return map[string]string{"requests-pace": req, "connects-pace": conn, "datagrams-pace": conn, "dns-pace": dns}
}

func paceLimits(l map[string]string, rate, portRate, minRate float64) map[string]string {
	for k, v := range stagePaces(rate, portRate, minRate) {
		l[k] = v
	}
	return l
}
