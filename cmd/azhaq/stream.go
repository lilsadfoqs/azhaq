package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/internal/webextract"
	"github.com/lilsadfoqs/azhaq/types"
)

// streamFound prints what a run finds as it finds it, once per map row: a
// long run is not silent for minutes before its map. A URL, a name that
// resolves and an address each print one line, under the key its map row
// has, however many collectors found it, and an open port prints one line
// under its row's key (address:port/tcp), when the scan reports it. Lines go
// to stdout before the map; with -json each is an object with "type":"found".
func streamFound(asJSON bool) func(types.Entity, types.Observation) {
	var mu sync.Mutex
	seen := map[string]bool{}
	enc := json.NewEncoder(os.Stdout)
	return func(_ types.Entity, o types.Observation) {
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			return
		}
		str := func(k string) string { s, _ := p[k].(string); return s }
		type line struct {
			kind, key, more string
			fields          map[string]any // more, as fields, for -json
		}
		var lines []line
		// A URL with an address for a host is also the address's row.
		urlLines := func(l line) {
			if l.key == "" {
				return
			}
			lines = append(lines, l)
			if ip := net.ParseIP(normalize.HostFromURL(l.key)); ip != nil {
				lines = append(lines, line{kind: "address", key: ip.String()})
			}
		}
		// The key a URL row has in the map; a URL that is no row is not
		// streamed.
		rowKey := func() string {
			k, err := engine.FoundKey(str("url"), str("role"))
			if err != nil || webextract.JunkURL(k) {
				return ""
			}
			return k
		}
		switch o.Kind {
		case "application":
			if st, ok := p["status"].(float64); ok && st > 0 {
				l := line{kind: "answer", key: rowKey(), more: fmt.Sprintf("[%d] %s", int(st), str("title")),
					fields: map[string]any{"status": int(st), "title": str("title")}}
				if p["catchall"] == true {
					// The page every unknown path gets: not a page of its own.
					l.more += "  (catch-all: the page any unknown path gets)"
					l.fields["catchall"] = true
				}
				urlLines(l)
			}
		case "url":
			urlLines(line{kind: "url", key: rowKey()})
		case "dns":
			ips, _ := p["ips"].([]any)
			if len(ips) > 0 && p["wildcard"] != true {
				lines = append(lines, line{kind: "name", key: str("fqdn")})
			}
			for _, v := range ips {
				if s, _ := v.(string); net.ParseIP(strings.TrimSpace(s)) != nil {
					lines = append(lines, line{kind: "address", key: net.ParseIP(strings.TrimSpace(s)).String()})
				}
			}
		case "ports":
			// One line per port row, as the map has them: the host's
			// address, the port and the protocol. A range's own row has no
			// ports of its own, and an address row names the ports it
			// found, so the open list repeated by each scan is not a key.
			if p["range"] == true {
				break
			}
			addr, host := str("ip"), str("host")
			if addr == "" {
				addr = host
			}
			if addr == "" {
				break
			}
			add := func(port any, proto, state, service string) {
				n, _ := port.(float64)
				if n <= 0 {
					return
				}
				key := net.JoinHostPort(addr, strconv.Itoa(int(n))) + "/" + proto
				fields := map[string]any{"ip": str("ip"), "host": host, "port": int(n), "protocol": proto, "state": state}
				more := state
				if service != "" {
					fields["service"] = service
					more += " " + service
				}
				if host != "" && host != addr {
					more = host + "  " + more
				}
				lines = append(lines, line{kind: "port", key: key, more: more, fields: fields})
			}
			rows := func(k, proto string) {
				list, _ := p[k].([]any)
				for _, v := range list {
					m, _ := v.(map[string]any)
					state, _ := m["state"].(string)
					if state == "" {
						state = "open"
					}
					svc, _ := m["service"].(string)
					add(m["port"], proto, state, svc)
				}
			}
			rows("services", "tcp")
			rows("udp_services", "udp")
		}
		mu.Lock()
		defer mu.Unlock()
		for _, l := range lines {
			if l.key == "" {
				continue
			}
			// A key is printed once, whichever way it was found first.
			if seen[l.key] {
				continue
			}
			seen[l.key] = true
			if asJSON {
				row := map[string]any{"type": "found", "kind": l.kind, "key": l.key, "collector": o.Collector}
				for k, v := range l.fields {
					row[k] = v
				}
				_ = enc.Encode(row)
				continue
			}
			fmt.Fprintln(os.Stdout, strings.TrimSpace(fmt.Sprintf("found  %-7s %s  %s", l.kind, l.key, l.more)))
		}
	}
}
