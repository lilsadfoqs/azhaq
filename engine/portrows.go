package engine

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/trannghiach/azhaq/internal/portscan"
	"github.com/trannghiach/azhaq/store"
	"github.com/trannghiach/azhaq/types"
)

// portRows are the open ports a port scan of e's address found, one row
// each with what answered: the newest scan of each address stands, since a
// scan a limit stopped is followed by the one that finishes it.
func portRows(e types.Entity, scope string, obs []types.StoredObservation) []MapEntry {
	type scan struct {
		host string
		tcp  []portscan.Open
		udp  []portscan.UDPPort
	}
	newest := map[string]scan{}
	var order []string
	for _, o := range obs {
		if o.Collector != "azhaq-ports" || o.Kind != "ports" {
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
		if _, ok := newest[id]; !ok {
			order = append(order, id)
		}
		host := p.Host
		if host == "" {
			host = p.IP
		}
		newest[id] = scan{host: host, tcp: p.Services, udp: p.UDP}
	}
	var out []MapEntry
	seen := map[string]bool{}
	add := func(host string, port int, proto, service, product, version string, proof []string) {
		key := net.JoinHostPort(host, strconv.Itoa(port)) + "/" + proto
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, MapEntry{
			Entity: types.Entity{ID: store.EntityID(types.TypePort, key), Type: types.TypePort, Key: key, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen},
			Scope:  scope, Role: "service", Service: service, Product: product, Version: version,
			Proof: strings.Join(proof, " "),
		})
	}
	for _, id := range order {
		s := newest[id]
		sort.Slice(s.tcp, func(i, j int) bool { return s.tcp[i].Port < s.tcp[j].Port })
		for _, o := range s.tcp {
			add(s.host, o.Port, "tcp", o.Service, o.Product, o.Version, portProof("open", o.Service, o.Product, o.Version, o.TLS, o.Title, o.Banner))
		}
		for _, u := range s.udp {
			add(s.host, u.Port, "udp", u.Service, u.Product, u.Version, portProof(u.State, u.Service, u.Product, u.Version, false, "", u.Banner))
		}
	}
	return out
}

// portProof is a port row's facts, in the order a reader looks for them.
func portProof(state, service, product, version string, tls bool, title, banner string) []string {
	parts := []string{"state=" + state}
	for _, kv := range [][2]string{{"service", service}, {"product", product}, {"version", version}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	if tls {
		parts = append(parts, "tls=true")
	}
	if title != "" {
		parts = append(parts, "title="+strconv.Quote(title))
	}
	if banner != "" && product == "" {
		parts = append(parts, "banner="+strconv.Quote(banner))
	}
	return parts
}
