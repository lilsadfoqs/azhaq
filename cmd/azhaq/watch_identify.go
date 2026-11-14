package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/store"
	"github.com/lilsadfoqs/azhaq/types"
)

// maxListed caps the services named on one line; the rest are counted.
const maxListed = 16

var uuidSeg = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// volatileSegment says a path segment is an identifier, a build hash or a
// placeholder: it changes with the data or the build, not with the app.
func volatileSegment(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") || uuidSeg.MatchString(s) {
		return true
	}
	digits, hex := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			hex++
		case r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F':
			hex++
		}
	}
	if digits == len(s) {
		return true
	}
	return hex == len(s) && len(s) >= 8 && digits > 0
}

// foldURL is the identity of a URL: scheme, host, port, the path with its
// identifier-like segments folded, and the sorted names of its query (never
// the values). Two URLs with one identity are one page to a person watching.
func foldURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if port == "" || port == "80" && scheme == "http" || port == "443" && scheme == "https" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = net.JoinHostPort(host, port)
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if volatileSegment(s) {
			segs[i] = "{}"
		}
	}
	path := strings.Join(segs, "/")
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + host + path
	var names []string
	seen := map[string]bool{}
	for _, kv := range strings.FieldsFunc(u.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		k, _, _ := strings.Cut(kv, "=")
		if n, err := url.QueryUnescape(k); err == nil {
			k = n
		}
		if k != "" && !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		out += "?" + strings.Join(names, "&")
	}
	return out
}

// foldedURLs are the identities of a run's URL entities.
func foldedURLs(st *store.Store) map[string]bool {
	out := map[string]bool{}
	ents, _ := st.Entities()
	for _, e := range ents {
		if e.Type == types.TypeURL {
			out[foldURL(e.Key)] = true
		}
	}
	return out
}

// portSvc is one open port as a run stored it.
type portSvc struct {
	port                      int
	proto                     string
	service, product, version string
}

func (s portSvc) key() string { return strconv.Itoa(s.port) + "/" + s.proto }

// name is what the run states of the service: product and version, else the
// service name it stored. Nothing is read from the port number.
func (s portSvc) name() string {
	if s.product != "" {
		return strings.TrimSpace(s.product + " " + s.version)
	}
	return s.service
}

// stated says the run named a product, not only a service.
func (s portSvc) stated() bool { return s.product != "" }

func (s portSvc) text() string { return strings.TrimSpace(s.key() + " " + s.name()) }

// svcsOf reads the open services of a ports row: TCP always, UDP only where
// the answer showed the port open.
func svcsOf(raw json.RawMessage) []portSvc {
	var row struct {
		Services []struct {
			Port                      int
			Service, Product, Version string
		} `json:"services"`
		UDP []struct {
			Port                      int
			State                     string
			Service, Product, Version string
		} `json:"udp_services"`
	}
	if json.Unmarshal(raw, &row) != nil {
		return nil
	}
	var out []portSvc
	for _, s := range row.Services {
		out = append(out, portSvc{s.Port, "tcp", s.Service, s.Product, s.Version})
	}
	for _, s := range row.UDP {
		if s.State == "open" {
			out = append(out, portSvc{s.Port, "udp", s.Service, s.Product, s.Version})
		}
	}
	return out
}

// mergeSvcs adds the services of a row; a port seen twice keeps its latest row.
func mergeSvcs(have, add []portSvc) []portSvc {
	for _, s := range add {
		if i := slices.IndexFunc(have, func(h portSvc) bool { return h.key() == s.key() }); i >= 0 {
			have[i] = s
		} else {
			have = append(have, s)
		}
	}
	return have
}

func sortSvcs(xs []portSvc) {
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].proto != xs[j].proto {
			return xs[i].proto > xs[j].proto // tcp first
		}
		return xs[i].port < xs[j].port
	})
}

// svcList is the services as one line part: "53/tcp BIND 9.11, 80/tcp nginx".
func svcList(xs []portSvc) string {
	xs = append([]portSvc(nil), xs...)
	sortSvcs(xs)
	var parts []string
	for i, s := range xs {
		if i == maxListed {
			parts = append(parts, fmt.Sprintf("… +%d more", len(xs)-maxListed))
			break
		}
		parts = append(parts, s.text())
	}
	return strings.Join(parts, ", ")
}

// techText is a wappalyzer entry, "Name:1.2", as a person reads it.
func techText(t string) string {
	name, ver, ok := strings.Cut(t, ":")
	if !ok || ver == "" {
		return name
	}
	return name + " " + ver
}

func techList(ts []string) string {
	var parts []string
	for i, t := range ts {
		if i == maxListed {
			parts = append(parts, fmt.Sprintf("… +%d more", len(ts)-maxListed))
			break
		}
		parts = append(parts, techText(t))
	}
	return strings.Join(parts, ", ")
}

// techChange names what a front page's technologies were and are, only
// when both runs stated some: a run that read none says nothing.
func techChange(old, neu []string) string {
	if len(old) == 0 || len(neu) == 0 {
		return ""
	}
	had := map[string]bool{}
	for _, t := range old {
		had[t] = true
	}
	has := map[string]bool{}
	for _, t := range neu {
		has[t] = true
	}
	var before, after []string
	for _, t := range old {
		if !has[t] {
			before = append(before, t)
		}
	}
	for _, t := range neu {
		if !had[t] {
			after = append(after, t)
		}
	}
	if len(before) == 0 && len(after) == 0 {
		return ""
	}
	side := func(ts []string) string {
		if len(ts) == 0 {
			return "none"
		}
		return techList(ts)
	}
	return "product: " + side(before) + " → " + side(after)
}

// portsChange is the line of a host whose open TCP ports differ: the ports
// added with what the run found on them, the ports removed, and the set now.
func portsChange(of, nf facts) string {
	had, has := map[string]bool{}, map[string]bool{}
	for _, p := range of.ports {
		had[p] = true
	}
	for _, p := range nf.ports {
		has[p] = true
	}
	named := map[string]portSvc{}
	for _, s := range nf.svcs {
		if s.proto == "tcp" {
			named[strconv.Itoa(s.port)] = s
		}
	}
	var parts []string
	for _, p := range nf.ports {
		if !had[p] {
			if s, ok := named[p]; ok {
				parts = append(parts, "+"+s.text())
			} else {
				parts = append(parts, "+"+p+"/tcp")
			}
		}
	}
	for _, p := range of.ports {
		if !has[p] {
			parts = append(parts, "-"+p+"/tcp")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	open := strings.Join(nf.ports, ",")
	if open == "" {
		open = "none"
	}
	return nf.host + ": " + strings.Join(parts, ", ") + " (open: " + open + ")"
}

// svcChanges lists the ports open in both runs where the product the run
// found is not the same: "host: 22/tcp OpenSSH 8.9 → OpenSSH 9.6".
func svcChanges(of, nf facts) []string {
	before := map[string]portSvc{}
	for _, s := range of.svcs {
		before[s.key()] = s
	}
	var out []string
	for _, s := range nf.svcs {
		if o, ok := before[s.key()]; ok && o.stated() && s.stated() && o.name() != s.name() {
			out = append(out, fmt.Sprintf("%s: %s %s → %s", nf.host, s.key(), o.name(), s.name()))
		}
	}
	return out
}

// danglingAnswers are the names a run's DNS answers show pointing nowhere,
// keyed by name and last target, with the line that says so; unsure holds
// the names whose only answer was a resolver failure, which says nothing.
func danglingAnswers(st *store.Store) (found map[string]string, unsure map[string]bool) {
	found, unsure = map[string]string{}, map[string]bool{}
	byHost := map[string]string{} // name to the key it is under in found
	obs, _ := st.Observations()
	for _, o := range obs {
		if o.Collector != "azhaq-dns" {
			continue
		}
		var p struct {
			FQDN     string `json:"fqdn"`
			Wildcard bool   `json:"wildcard"`
			Degraded bool   `json:"degraded"`
			Dangling *struct {
				Chain  []string `json:"chain"`
				Target string   `json:"target"`
				Rcode  string   `json:"rcode"`
			} `json:"dangling"`
			Takeover *struct {
				Service string `json:"service"`
				Status  string `json:"status"`
			} `json:"takeover"`
		}
		if json.Unmarshal(o.Payload, &p) != nil || p.FQDN == "" {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(p.FQDN, "."))
		if p.Degraded {
			unsure[host] = true
			continue
		}
		delete(unsure, host)
		if k, ok := byHost[host]; ok { // the latest answer wins
			delete(found, k)
			delete(byHost, host)
		}
		if p.Wildcard || p.Dangling == nil || p.Dangling.Target == "" {
			continue
		}
		chain := p.Dangling.Chain
		if len(chain) == 0 {
			chain = []string{p.Dangling.Target}
		}
		rcode := p.Dangling.Rcode
		if rcode == "" {
			rcode = "NXDOMAIN"
		}
		why := rcode
		if t := p.Takeover; t != nil && t.Service != "" {
			what := "takeover " + t.Status + ": " + t.Service
			if t.Service == "domain" {
				what = "takeover " + t.Status + ": the target's domain may be free to register"
			}
			why += "; " + what
		}
		k := host + "\x00" + p.Dangling.Target
		found[k] = host + " → " + strings.Join(chain, " → ") + " (" + why + ")"
		byHost[host] = k
	}
	return found, unsure
}

// newDangling are the names that point nowhere now and did not before: a
// name not dangling in the previous run, or new, but not one whose previous
// answer was only a failed lookup.
func newDangling(old, neu *store.Store) []string {
	was, unsure := danglingAnswers(old)
	now, _ := danglingAnswers(neu)
	var out []string
	for k, line := range now {
		if _, ok := was[k]; ok {
			continue
		}
		if host, _, _ := strings.Cut(k, "\x00"); unsure[host] {
			continue
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}
