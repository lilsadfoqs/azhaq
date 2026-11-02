package engine

import (
	"encoding/json"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lilsadfoqs/azhaq/internal/portscan"
	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// portRows are the open ports a port scan of e's address found, one row
// each with what answered: the newest scan of each address stands, since a
// scan a limit stopped is followed by the one that finishes it. The ports an
// imported scan (naabu writes one line per port) names are rows too, those
// of azhaq's own scan first, since they say what answered.
func portRows(e types.Entity, scope string, obs []types.StoredObservation) []MapEntry {
	type scan struct {
		host string
		ip   string
		at   time.Time
		tcp  []portscan.Open
		udp  []portscan.UDPPort
	}
	newest := map[string]scan{}
	imported := map[string]scan{}
	names := map[string][]string{} // by address: the names it was scanned under
	var order []string
	for _, o := range obs {
		if o.Kind != "ports" {
			continue
		}
		var p struct {
			Host     string             `json:"host"`
			IP       string             `json:"ip"`
			Range    bool               `json:"range"`
			Services []portscan.Open    `json:"services"`
			UDP      []portscan.UDPPort `json:"udp_services"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.Range {
			continue
		}
		id := p.IP
		if id == "" {
			id = p.Host
		}
		_, haveOwn := newest[id]
		_, haveImported := imported[id]
		if !haveOwn && !haveImported {
			order = append(order, id)
		}
		host := p.Host
		if host == "" {
			host = p.IP
		}
		if host != "" && host != p.IP {
			names[id] = addName(names[id], host)
		}
		if o.Collector != "azhaq-ports" {
			// Each imported line adds its ports to the address's.
			s := imported[id]
			if !haveImported || o.ObservedAt.After(s.at) {
				s.at = o.ObservedAt
			}
			s.host, s.ip = host, p.IP
			s.tcp = append(s.tcp, p.Services...)
			s.udp = append(s.udp, p.UDP...)
			imported[id] = s
			continue
		}
		newest[id] = scan{host: host, ip: p.IP, at: o.ObservedAt, tcp: p.Services, udp: p.UDP}
	}
	var out []MapEntry
	seen := map[string]bool{}
	add := func(id string, s scan, port int, proto, state, service, product, version string, proof []string) {
		// An endpoint is its address, however many names point to it: the
		// names are on the row.
		addr := s.ip
		if addr == "" {
			addr = s.host
		}
		key := net.JoinHostPort(addr, strconv.Itoa(port)) + "/" + proto
		if port <= 0 || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, MapEntry{
			Entity: types.Entity{ID: store.EntityID(types.TypePort, key), Type: types.TypePort, Key: key, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen},
			Scope:  scope, Role: "service", Service: service, Product: product, Version: version,
			State: state, Proof: strings.Join(proof, " "), at: s.at, Names: slices.Sorted(slices.Values(names[id])),
		})
	}
	for _, id := range order {
		s := newest[id]
		if im, ok := imported[id]; ok {
			if s.host == "" {
				s.host, s.ip, s.at = im.host, im.ip, im.at
			}
			s.tcp = append(s.tcp[:len(s.tcp):len(s.tcp)], im.tcp...)
			s.udp = append(s.udp[:len(s.udp):len(s.udp)], im.udp...)
		}
		sort.SliceStable(s.tcp, func(i, j int) bool { return s.tcp[i].Port < s.tcp[j].Port })
		for _, o := range s.tcp {
			add(id, s, o.Port, "tcp", "open", o.Service, o.Product, o.Version, portProof("open", o.Service, o.Product, o.Version, o.Extra, o.TLS, o.TLSVers, o.Cipher, o.Title, o.Banner))
		}
		for _, u := range s.udp {
			add(id, s, u.Port, "udp", u.State, u.Service, u.Product, u.Version, portProof(u.State, u.Service, u.Product, u.Version, "", false, "", "", "", u.Banner))
		}
	}
	return out
}

// portProof is a port row's facts, in the order a reader looks for them.
func portProof(state, service, product, version, extra string, tls bool, tlsVers, cipher, title, banner string) []string {
	parts := []string{"state=" + state}
	for _, kv := range [][2]string{{"service", service}, {"product", product}, {"version", version}, {"extrainfo", extra}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	if tls {
		parts = append(parts, "tls=true")
		for _, kv := range [][2]string{{"tls_version", tlsVers}, {"cipher", cipher}} {
			if kv[1] != "" {
				parts = append(parts, kv[0]+"="+kv[1])
			}
		}
	}
	if title != "" {
		parts = append(parts, "title="+strconv.Quote(title))
	}
	if banner != "" && product == "" {
		parts = append(parts, "banner="+strconv.Quote(banner))
	}
	return parts
}

// addPortRows puts an address's port rows in out, one row for each
// host, port and protocol: a prefix's scan and the scan of an address in
// it list the same port. Of two rows the newer scan stands, with the first
// time either saw it, and a confirmed open is never replaced by open|filtered.
func addPortRows(out []MapEntry, at map[string]int, rows []MapEntry) []MapEntry {
	for _, r := range rows {
		i, dup := at[r.Entity.Key]
		if !dup {
			at[r.Entity.Key] = len(out)
			out = append(out, r)
			continue
		}
		old := out[i]
		first, last := old.Entity.FirstSeen, old.Entity.LastSeen
		if !r.Entity.FirstSeen.IsZero() && (first.IsZero() || r.Entity.FirstSeen.Before(first)) {
			first = r.Entity.FirstSeen
		}
		if r.Entity.LastSeen.After(last) {
			last = r.Entity.LastSeen
		}
		scope := old.Scope
		if r.Scope == "target" {
			scope = r.Scope
		}
		names := old.Names
		for _, n := range r.Names {
			names = addName(slices.Clone(names), n)
		}
		slices.Sort(names)
		if (r.State == "open" && old.State != "open") || (r.at.After(old.at) && (old.State != "open" || r.State == "open")) {
			old = r
		}
		old.Entity.FirstSeen, old.Entity.LastSeen, old.Scope, old.Names = first, last, scope, names
		out[i] = old
	}
	return out
}
