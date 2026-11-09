package connector

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/normalize"
	"github.com/lilsadfoqs/azhaq/types"
)

// Tools azhaq stands in for besides the ones that write one JSON object per
// line: what they write is taken in as the tool's own word, never as a
// request of azhaq's (no row of it is visited).
const (
	FormatArjun     = "arjun"
	FormatGowitness = "gowitness"
	FormatAsnmap    = "asnmap"
	FormatNmap      = "nmap"
)

// arjunFacts reads arjun's -oJ file: one JSON object keyed by page URL, each
// holding the parameter names found, the method they were found with and the
// headers used. ok is false when raw is not that shape.
func arjunFacts(raw []byte) (facts []Fact, n int, ok bool) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || len(doc) == 0 {
		return nil, 0, false
	}
	pages := make([]string, 0, len(doc))
	for k, v := range doc {
		var r struct {
			Params *[]string `json:"params"`
		}
		if !strings.HasPrefix(k, "http://") && !strings.HasPrefix(k, "https://") || json.Unmarshal(v, &r) != nil || r.Params == nil {
			return nil, 0, false
		}
		pages = append(pages, k)
	}
	sort.Strings(pages)
	for _, page := range pages {
		var r struct {
			Params []string `json:"params"`
			Method string   `json:"method"`
		}
		_ = json.Unmarshal(doc[page], &r)
		u, err := normalize.URL(page)
		if err != nil || len(r.Params) == 0 {
			continue
		}
		n++
		row := map[string]any{"url": u, "via": "arjun", "method": strings.ToUpper(r.Method)}
		switch m := strings.ToUpper(r.Method); m {
		case "", "GET":
			row["method"], row["params"] = "GET", r.Params
		default:
			// POST names go in the body, in the form the method says.
			media := map[string]string{"JSON": "application/json", "XML": "application/xml"}[m]
			if media == "" {
				media = "application/x-www-form-urlencoded"
			}
			row["methods"], row["body"] = []string{"POST"}, r.Params
			row["ops"] = []any{map[string]any{"method": "POST", "body": r.Params, "body_type": media}}
		}
		facts = append(facts, observation(urlSeed(u), "arjun", "params", row))
	}
	return facts, n, true
}

// gowitnessFacts reads one line of gowitness's JSON lines: the page it
// loaded and what it saw. It is a hint of the URL, with the answer kept on
// it: azhaq asked nothing.
func gowitnessFacts(m map[string]any) []Fact {
	u, err := normalize.URL(text(m["url"]))
	if err != nil {
		return nil
	}
	p := map[string]any{"url": u, "via": "gowitness"}
	if st, ok := m["response_code"].(float64); ok && st > 0 {
		p["status"] = int(st)
	}
	if n, ok := m["content_length"].(float64); ok && n >= 0 {
		p["length"] = int(n)
	}
	for from, to := range map[string]string{"title": "title", "protocol": "protocol", "file_name": "screenshot", "perception_hash": "perception_hash", "failed_reason": "error"} {
		if v := text(m[from]); v != "" {
			p[to] = v
		}
	}
	if f, err := normalize.URL(text(m["final_url"])); err == nil && f != u {
		p["final_url"] = f
	}
	if failed, _ := m["failed"].(bool); failed {
		p["failed"] = true
	}
	var tech []string
	if ts, _ := m["technologies"].([]any); len(ts) > 0 {
		for _, t := range ts {
			switch t := t.(type) {
			case string:
				tech = append(tech, t)
			case map[string]any:
				if v := text(t["value"]); v != "" {
					tech = append(tech, v)
				}
			}
		}
	}
	if len(tech) > 0 {
		p["tech"] = tech
	}
	return []Fact{observation(urlSeed(u), "gowitness", "url", p)}
}

// asnmapFacts reads one line of asnmap's -json (as_number, as_name,
// as_country, and as_range, the prefixes; azhaq asn writes one prefix).
func asnmapFacts(m map[string]any) []Fact {
	asn := strings.ToUpper(strings.TrimSpace(text(m["as_number"])))
	if asn != "" && !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}
	if n, ok := m["as_number"].(float64); ok {
		asn = "AS" + strconv.Itoa(int(n))
	}
	if len(asn) < 3 {
		return nil
	}
	prefixes := strings2(m["as_range"])
	if p := text(m["prefix"]); p != "" {
		prefixes = append(prefixes, p)
	}
	var norm []string
	for _, p := range prefixes {
		if pf, err := netip.ParsePrefix(strings.TrimSpace(p)); err == nil {
			norm = append(norm, pf.Masked().String())
		}
	}
	row := map[string]any{"asn": asn, "count": len(norm), "prefixes": norm, "via": "asnmap", "source": "asnmap"}
	if v := text(m["as_name"]); v != "" {
		row["holder"] = v
	}
	if v := text(m["as_country"]); v != "" {
		row["country"] = v
	}
	facts := []Fact{observation(types.Seed{Type: types.TypeASN, Keys: map[string]string{"asn": asn}}, "asnmap", "prefixes", row)}
	for _, p := range norm {
		facts = append(facts, Fact{Kind: "entity", EntityType: types.TypePrefix, EntityKey: p})
	}
	return facts
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapFile struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			ID       int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string `xml:"name,attr"`
				Product   string `xml:"product,attr"`
				Version   string `xml:"version,attr"`
				ExtraInfo string `xml:"extrainfo,attr"`
				Tunnel    string `xml:"tunnel,attr"`
			} `xml:"service"`
			Scripts []nmapScript `xml:"script"`
		} `xml:"ports>port"`
		HostScripts []nmapScript `xml:"hostscript>script"`
	} `xml:"host"`
}

// isNmapXML says raw looks like an nmap -oX file.
func isNmapXML(raw []byte) bool {
	head := raw[:min(len(raw), 2048)]
	return bytes.HasPrefix(raw, []byte("<")) && bytes.Contains(head, []byte("<nmaprun")) || bytes.HasPrefix(raw, []byte("<?xml")) && bytes.Contains(raw, []byte("<nmaprun"))
}

// nmapFacts reads an nmap -oX file: each host that is up, its names, and the
// ports that answered open with the service nmap named, the product and
// version it read, and what its scripts printed. Closed and filtered ports
// say nothing of a service and are not taken. n counts the ports read.
func nmapFacts(raw []byte) (facts []Fact, n int, err error) {
	var f nmapFile
	if err := xml.Unmarshal(raw, &f); err != nil {
		return nil, 0, fmt.Errorf("not an nmap XML file: %w", err)
	}
	for _, h := range f.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		var names []string
		for _, hn := range h.Hostnames {
			if x := normalize.Hostname(hn.Name); x != "" && !contains(names, x) {
				names = append(names, x)
				facts = append(facts, Fact{Kind: "entity", EntityType: types.TypeHostname, EntityKey: x})
			}
		}
		var tcp, udp []map[string]any
		var openPorts []string
		for _, p := range h.Ports {
			st := p.State.State
			svc := map[string]any{"port": p.ID}
			for k, v := range map[string]string{"service": p.Service.Name, "product": p.Service.Product, "version": p.Service.Version, "extrainfo": p.Service.ExtraInfo} {
				if v != "" {
					svc[k] = v
				}
			}
			if len(p.Scripts) > 0 {
				scripts := make([]map[string]any, 0, len(p.Scripts))
				for _, s := range p.Scripts {
					scripts = append(scripts, map[string]any{"id": s.ID, "output": s.Output})
				}
				svc["scripts"] = scripts
			}
			switch {
			case p.ID <= 0:
				continue
			case p.Protocol == "tcp" && st == "open":
				if p.Service.Tunnel == "ssl" {
					svc["tls"] = true
				}
				tcp = append(tcp, svc)
				openPorts = append(openPorts, strconv.Itoa(p.ID))
			case p.Protocol == "udp" && (st == "open" || st == "open|filtered"):
				svc["state"] = st
				udp = append(udp, svc)
			default:
				continue
			}
			n++
		}
		var ips []string
		for _, a := range h.Addresses {
			if (a.Type == "ipv4" || a.Type == "ipv6") && net.ParseIP(a.Addr) != nil {
				ips = append(ips, net.ParseIP(a.Addr).String())
			}
		}
		if len(ips) == 0 && len(names) > 0 {
			ips = []string{names[0]}
		}
		for _, ip := range ips {
			facts = append(facts, Fact{Kind: "entity", EntityType: hostSeed(ip).Type, EntityKey: hostSeed(ip).Key()})
			if len(tcp)+len(udp) == 0 && len(h.HostScripts) == 0 {
				continue
			}
			row := map[string]any{"host": ip, "ip": ip, "via": "nmap", "services": orEmpty(tcp), "udp_services": orEmpty(udp)}
			if net.ParseIP(ip) == nil {
				delete(row, "ip")
			}
			if len(names) > 0 {
				row["names"] = names
			}
			if len(openPorts) > 0 {
				row["open"] = openPorts
			}
			if len(h.HostScripts) > 0 {
				scripts := make([]map[string]any, 0, len(h.HostScripts))
				for _, s := range h.HostScripts {
					scripts = append(scripts, map[string]any{"id": s.ID, "output": s.Output})
				}
				row["host_scripts"] = scripts
			}
			facts = append(facts, observation(hostSeed(ip), "nmap", "ports", row))
		}
	}
	return facts, n, nil
}

func orEmpty(v []map[string]any) []map[string]any {
	if v == nil {
		return []map[string]any{}
	}
	return v
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
