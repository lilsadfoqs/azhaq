package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
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
// has, however many collectors found it; an open-ports line stands for the
// host's port rows (host:port/tcp). Lines go to stdout before the map; with
// -json each is an object with "type":"found".
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
			if open, _ := p["open"].([]any); len(open) > 0 {
				l := line{kind: "ports", key: str("host"), more: fmt.Sprint(open), fields: map[string]any{"ip": str("ip"), "open": open}}
				if l.key == "" {
					l.key = str("ip")
				} else if ip := str("ip"); ip != "" && ip != l.key {
					l.more = ip + " " + l.more
				}
				lines = append(lines, l)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		for _, l := range lines {
			if l.key == "" {
				continue
			}
			// A key is printed once, whichever way it was found first; its
			// ports line is a separate key, as the port rows are.
			id := l.key
			if l.kind == "ports" {
				id = "ports " + l.key + " " + l.more
			}
			if seen[id] {
				continue
			}
			seen[id] = true
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
