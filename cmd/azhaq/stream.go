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

// line is one found line: more is its tail, fields the same as fields for
// -json.
type line struct {
	kind, key, more string
	fields          map[string]any
}

const catchAllNote = "  (catch-all: the page any unknown path gets)"

// streamFound prints what a run finds as it finds it, once per map row: a
// long run is not silent for minutes before its map. A URL, a name that
// resolves and an address each print one line, under the key its map row
// has, however many collectors found it, and an open port prints one line
// under its row's key (address:port/tcp), when the scan reports it. Lines go
// to stdout before the map; with -json each is an object with "type":"found".
//
// A URL the map folds into a templated row (/redirect?to={v}) is not a row
// of its own, and which template a row ends with is known only at the end:
// those are held, and end prints each templated row once, under the key the
// map gives it, before the map.
func streamFound(asJSON bool) func(types.Entity, types.Observation) {
	see, _ := newStream(asJSON)
	return see
}

// newStream is streamFound with the end of the run: end takes the map's rows
// and prints the templated ones.
func newStream(asJSON bool) (see func(types.Entity, types.Observation), end func([]engine.MapEntry)) {
	var mu sync.Mutex
	seen := map[string]bool{}
	heldBy := map[string]string{} // a templated URL, or its template, held back -> the collector that found it first
	dnsBy := map[string]string{}  // a name looked up -> the collector that asked
	enc := json.NewEncoder(os.Stdout)
	emit := func(kind, key, more, collector string, fields map[string]any) {
		if seen[key] {
			return
		}
		seen[key] = true
		if asJSON {
			row := map[string]any{"type": "found", "kind": kind, "key": key, "collector": collector}
			for k, v := range fields {
				row[k] = v
			}
			_ = enc.Encode(row)
			return
		}
		fmt.Fprintln(os.Stdout, strings.TrimSpace(fmt.Sprintf("found  %-7s %s  %s", kind, key, more)))
	}
	end = func(rows []engine.MapEntry) {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range rows {
			// A name with no address, and a domain, are rows of the map that
			// no resolving answer streamed: each is a line at the end.
			if t := r.Entity.Type; t == types.TypeHostname || t == types.TypeDomain {
				coll := dnsBy[r.Entity.Key]
				if coll == "" {
					coll = "azhaq"
				}
				emit("name", r.Entity.Key, "", coll, nil)
				continue
			}
			if r.Entity.Type == types.TypeURL && r.Template == "" {
				// A row no answer streamed (a request held back, a URL not
				// asked) still has its line: the stream holds every row.
				if !seen[r.Entity.Key] {
					emit("url", r.Entity.Key, "("+r.Coverage+")", "azhaq", map[string]any{"coverage": r.Coverage})
				}
				continue
			}
			if r.Entity.Type != types.TypeURL {
				continue
			}
			key := r.Entity.Key
			if r.Count > 1 {
				key = r.Template
			}
			coll, ok := heldBy[r.Entity.Key]
			if !ok {
				if coll, ok = heldBy[r.Template]; !ok {
					continue
				}
			}
			if r.Status <= 0 {
				emit("url", key, "", coll, nil)
				continue
			}
			l := line{kind: "answer", more: fmt.Sprintf("[%d] %s", r.Status, r.Title),
				fields: map[string]any{"status": r.Status, "title": r.Title}}
			if r.Coverage == "catchall" {
				l.more += catchAllNote
				l.fields["catchall"] = true
			}
			emit(l.kind, key, l.more, coll, l.fields)
		}
	}
	see = func(_ types.Entity, o types.Observation) {
		var p map[string]any
		if json.Unmarshal(o.Payload, &p) != nil {
			return
		}
		str := func(k string) string { s, _ := p[k].(string); return s }
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
					l.more += catchAllNote
					l.fields["catchall"] = true
				}
				urlLines(l)
			}
		case "url":
			urlLines(line{kind: "url", key: rowKey()})
		case "dns":
			mu.Lock()
			dnsBy[normalize.Hostname(str("fqdn"))] = o.Collector
			mu.Unlock()
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
			if (l.kind == "url" || l.kind == "answer") && webextract.Templated(l.key) {
				if _, ok := heldBy[l.key]; !ok {
					heldBy[l.key] = o.Collector
				}
				if _, ok := heldBy[webextract.Template(l.key)]; !ok {
					heldBy[webextract.Template(l.key)] = o.Collector
				}
				continue
			}
			// A key is printed once, whichever way it was found first.
			emit(l.kind, l.key, l.more, o.Collector, l.fields)
		}
	}
	return see, end
}
