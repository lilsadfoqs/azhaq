package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lilsadfoqs/azhaq/internal/fetch"
	"github.com/lilsadfoqs/azhaq/internal/lazyre"
	"github.com/lilsadfoqs/azhaq/types"
)

// Services reads the product-and-version services a run's observations
// already confirmed: the services of a port scan's rows (their product
// and version are what the service itself stated), and the Server
// header of a web answer azhaq-http recorded. Nothing is asked of any
// target to build this list. A service with no version yet is left
// out: there is nothing to match an advisory against.
func Services(obs []types.StoredObservation) []Service {
	return services(obs, true)
}

// ServicesAnyVersion is Services without the version: the named
// services a port scan recorded even when nothing named their version.
// A read-only verification (internal/verify) checks those too — its
// one read is how the version is learned — so it reads this list and
// picks the names it has a check for.
func ServicesAnyVersion(obs []types.StoredObservation) []Service {
	return services(obs, false)
}

func services(obs []types.StoredObservation, needVersion bool) []Service {
	var out []Service
	seen := map[string]bool{}
	add := func(s Service) {
		if needVersion {
			// Matching an advisory needs a stated product and version.
			if s.Product == "" || s.Version == "" {
				return
			}
		} else if s.Service == "" && s.Product == "" {
			// A verification check keys on the service name alone.
			return
		}
		if needVersion {
			out = append(out, s) // merged by listener below
			return
		}
		key := fmt.Sprintf("%s|%d|%s|%s|%s", s.Target(), s.Port, s.Proto, ProductKey(s.Product), s.Version)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
	}
	for _, o := range obs {
		switch o.Collector {
		case "azhaq-ports":
			var row struct {
				Host     string `json:"host"`
				IP       string `json:"ip"`
				Services []struct {
					Port    int    `json:"port"`
					Service string `json:"service"`
					Product string `json:"product"`
					Version string `json:"version"`
					Banner  string `json:"banner"`
					TLS     bool   `json:"tls"`
				} `json:"services"`
				UDP []struct {
					Port    int    `json:"port"`
					Service string `json:"service"`
					Product string `json:"product"`
					Version string `json:"version"`
					Banner  string `json:"banner"`
				} `json:"udp_services"`
			}
			if json.Unmarshal(o.Payload, &row) != nil {
				continue
			}
			host := row.Host
			for _, s := range row.Services {
				svc := Service{Host: host, IP: row.IP, Port: s.Port, Proto: "tcp", Service: strings.TrimSuffix(s.Service, "?"),
					Product: s.Product, Version: s.Version, Banner: s.Banner, TLS: s.TLS, ObservedAt: o.ObservedAt}
				svc.Origin = webOrigin(svc)
				add(svc)
			}
			for _, s := range row.UDP {
				add(Service{Host: host, IP: row.IP, Port: s.Port, Proto: "udp", Service: strings.TrimSuffix(s.Service, "?"),
					Product: s.Product, Version: s.Version, Banner: s.Banner, ObservedAt: o.ObservedAt})
			}
		case "azhaq-http":
			var row struct {
				URL    string   `json:"url"`
				Server string   `json:"server"`
				Tech   []string `json:"tech"`
			}
			if json.Unmarshal(o.Payload, &row) != nil || (row.Server == "" && len(row.Tech) == 0) {
				continue
			}
			u, err := url.Parse(row.URL)
			if err != nil || u.Hostname() == "" {
				continue
			}
			port := 0
			if p, err := strconv.Atoi(u.Port()); err == nil {
				port = p
			} else if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
			web := func(product, version, banner, source string) Service {
				return Service{Host: u.Hostname(), Port: port, Proto: "tcp", Service: u.Scheme,
					Product: product, Version: version, Origin: u.Scheme + "://" + u.Host,
					Banner: banner, Source: source, ObservedAt: o.ObservedAt, From: row.URL}
			}
			if row.Server != "" {
				product, version := ProductVersion(row.Server)
				add(web(product, version, "Server: "+row.Server, SourceServer))
			}
			// The technologies the page's own markup and headers name with a
			// version ("WordPress:6.4.2"): what the site itself states.
			for _, t := range row.Tech {
				if name, version, ok := strings.Cut(t, ":"); ok && name != "" && version != "" && version[0] >= '0' && version[0] <= '9' {
					add(web(name, version, "technology: "+t, SourceTech))
				}
			}
		}
	}
	addrs := NameAddrs(obs)
	if needVersion {
		out = mergeListeners(out, addrs)
	}
	return append(out, namedApps(obs, out, addrs, needVersion)...)
}

// namedApps are the applications a name's root page names, as services of that
// name and port, besides what the listener's rows already say: an application
// the listener's row names for the same name is not repeated, nor a plain web
// server the listener names for any name. With needVersion, only the ones a
// version was stated for.
func namedApps(obs []types.StoredObservation, have []Service, addrs map[string]string, needVersion bool) []Service {
	apps := pageApps(obs)
	if len(apps) == 0 {
		return nil
	}
	listenerOf := func(s Service) string {
		addr := normIP(s.IP)
		if addr == "" {
			addr = normIP(s.Host)
		}
		if addr == "" {
			addr = addrs[strings.ToLower(s.Host)]
		}
		return listenerKey(addr, s.Host, s.Port, s.Proto)
	}
	by := map[string][]Service{} // listener + product → what the listener's rows name
	for _, s := range have {
		k := listenerOf(s) + "|" + ProductKey(s.Product)
		by[k] = append(by[k], s)
	}
	var out []Service
	for _, a := range apps {
		if needVersion && a.Version == "" {
			continue
		}
		dup := false
		for _, e := range by[listenerOf(a.Service)+"|"+ProductKey(a.Product)] {
			if a.Plain || sameName(e, a.Service) && (a.Version == "" || e.Version == a.Version || refines(e.Version, a.Version)) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, a.Service)
		}
	}
	return out
}

// sameName says a listener's row was read from the name's own page: its host,
// or the page its version was read from.
func sameName(e, a Service) bool {
	if strings.EqualFold(e.Host, a.Host) {
		return true
	}
	if u, err := url.Parse(e.From); err == nil && e.From != "" {
		return strings.EqualFold(u.Hostname(), a.Host)
	}
	return false
}

// webOrigin is the origin a confirmation reads for a port-scan service,
// when it is a web one: http or https by what the scan named it, a TLS
// port https. Anything else has none, and is not read over HTTP.
func webOrigin(s Service) string {
	host := s.Host
	if host == "" {
		host = s.IP
	}
	if host == "" || s.Port == 0 {
		return ""
	}
	scheme := ""
	switch {
	case s.Service == "http":
		scheme = "http"
	case s.Service == "https" || s.TLS:
		scheme = "https"
	}
	if scheme == "" {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(s.Port))
}

// Confirmer makes the one benign read of a confirmation. Client is the
// client its caller holds to the scope, the ledger and the pace (an
// egress target client); Spend counts the read against the run's budget
// before it is sent, as every request to a target is counted. Both are
// the caller's: this package asks for nothing on its own authority.
type Confirmer struct {
	Client *http.Client
	Spend  func(ctx context.Context) error
}

// Confirm reads what svc already exposes and says how far it settles
// lead: observed when the read itself decides where the version stands
// in the advisory's range (and the advisory names no other
// precondition), inferred when it narrows the match but leaves
// something named unknown, claimed when nothing read settles anything.
// The read is one GET of the advisory's confirm path, or of / to read
// the version and Server headers when it names none: no body, no other
// method, no credential, nothing that could trigger the issue. A
// service with no web origin is not read at all. err is a read that
// failed (a refusal, no answer): the lead stays claimed and the caller
// counts the failure as a degraded result.
func (c Confirmer) Confirm(ctx context.Context, adv Advisory, svc Service) (confidence, read string, err error) {
	if conf, why, ok := NoRead(svc); ok {
		return conf, why, nil
	}
	sig, err := c.Read(ctx, svc, adv.ReadPath())
	if err != nil {
		return Claimed, "", err
	}
	conf, read := sig.Judge(adv, svc)
	return conf, read, nil
}

// NoRead says a service is not read at all, and why: it has no web origin.
func NoRead(svc Service) (confidence, read string, ok bool) {
	if svc.Origin == "" {
		return Claimed, "not read: the service is not a web service, so the only signal is the banner azhaq already holds; a read that could settle it would have to speak its protocol again, which confirmation does not do", true
	}
	return "", "", false
}

// ReadPath is the path an advisory's confirmation reads: its own, else /.
func (a Advisory) ReadPath() string {
	if p := a.confirmPath(); p != "" {
		return p
	}
	return "/"
}

// Signal is what one confirmation read showed: the answer's status line and
// the product and version it states, if any. One read is enough for every
// advisory that names the same path, each judged against it (Judge).
type Signal struct {
	Path     string
	What     string // "GET / answered 200"
	Product  string
	Version  string
	From     string // where the version was read (the Server header, the body)
	Mentions bool   // the answer names the product, with no version
}

// Read makes the one read of path on the service's origin: one GET, no
// body, no other method, no credential, nothing that could trigger an
// issue. It spends from the budget first and goes through the client its
// caller holds; err is a read that failed or was refused.
func (c Confirmer) Read(ctx context.Context, svc Service, path string) (Signal, error) {
	if err := ValidConfirmPath(path); err != nil {
		return Signal{}, err
	}
	if c.Spend != nil {
		if err := c.Spend(ctx); err != nil {
			return Signal{}, err
		}
	}
	client := c.Client
	if client == nil {
		// Only egress opens a connection: without a client asked from
		// it there is nothing to read with, and the caller hears so
		// instead of a quiet direct dial.
		return Signal{}, fmt.Errorf("advisory confirmation has no client: ask egress for one")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc.Origin+path, nil)
	if err != nil {
		return Signal{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Signal{}, err
	}
	fetch.BoundNote(resp, "GET "+path) // a stream that never ends is cut, and the run says so
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	sig := Signal{Path: path, What: fmt.Sprintf("GET %s answered %d", path, resp.StatusCode)}
	// The signal: a product and version the answer states, in its
	// Server header first, then its body.
	sig.Product, sig.Version = ProductVersion(resp.Header.Get("Server"))
	sig.From = "the Server header"
	if sig.Version == "" {
		if p, v := productVersionIn(string(body), svc.Product); v != "" {
			sig.Product, sig.Version, sig.From = p, v, "the body of "+path
		}
	}
	sig.Mentions = strings.Contains(strings.ToLower(string(body)), strings.ToLower(svc.Product))
	return sig, nil
}

// Judge says how far the read settles adv for svc: observed when the
// version it states decides where the version stands in the advisory's
// range (and the advisory names no other precondition), inferred when it
// narrows the match but leaves something named unknown, claimed when
// nothing read settles anything.
func (sig Signal) Judge(adv Advisory, svc Service) (confidence, read string) {
	what, product, version, from := sig.What, sig.Product, sig.Version, sig.From
	switch {
	case version == "":
		if product != "" || sig.Mentions {
			return Inferred, what + "; it names the product but no version, so the version seen stands unread and the precondition is still open"
		}
		return Claimed, what + "; it states no product or version, so nothing was read that settles the match"
	case !sameProduct(product, svc.Product) && product != "":
		return Inferred, fmt.Sprintf("%s; %s names %s %s, not the %s of the match, so it does not settle this lead", what, from, product, version, svc.Product)
	}
	// A version was read. Where it stands in the range decides, when
	// the comparison is exact and no other precondition is named.
	st, _, why := evalForAdvisory(adv, svc.Product, version)
	switch {
	case st == stateUncertain:
		return Inferred, fmt.Sprintf("%s; %s states version %s, which %s", what, from, version, "could not be compared with the advisory's range: "+why)
	case adv.precondition() != "":
		return Inferred, fmt.Sprintf("%s; %s states version %s, which settles the version but not the precondition (%s), which the read does not show", what, from, version, adv.precondition())
	case st == stateIn:
		return Observed, fmt.Sprintf("%s; %s states %s %s, inside the advisory's range", what, from, svc.Product, version)
	default:
		return Observed, fmt.Sprintf("%s; %s states %s %s, outside the advisory's range: the version seen does not stand", what, from, svc.Product, version)
	}
}

// evalForAdvisory is where version stands in adv's entries for product.
func evalForAdvisory(adv Advisory, product, version string) (state, string, string) {
	for _, aff := range adv.Affected {
		if sameProduct(aff.Package.Name, product) {
			return evalAffected(aff, version)
		}
	}
	return stateUncertain, "", "the advisory names no entry for this product"
}

var jsonVersion = lazyre.New(`"version"\s*:\s*"v?([0-9][^"]*)"`)

// productVersionIn finds "product version" or "product/version" naming
// product in text, on one line.
func productVersionIn(text, product string) (string, string) {
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(strings.ToLower(line), strings.ToLower(product)) {
			continue
		}
		if p, v := ProductVersion(line); v != "" && sameProduct(p, product) {
			return p, v
		}
		// A JSON build line: "version": "1.18.0" on the product's line.
		if m := jsonVersion.FindStringSubmatch(line); m != nil {
			return product, m[1]
		}
	}
	return "", ""
}

// NameAddrs is the address each name answered from, as the run recorded it:
// a scan row's own, the one a web answer came from, and, for a name that
// resolved to exactly one address, its DNS answer. A name with two
// addresses and no row that says which is left out: it is not told apart.
func NameAddrs(obs []types.StoredObservation) map[string]string {
	out := map[string]string{}
	set := func(name, ip string, force bool) {
		name, ip = strings.ToLower(strings.TrimSpace(name)), normIP(ip)
		if name == "" || ip == "" || normIP(name) != "" {
			return
		}
		if _, ok := out[name]; !ok || force {
			out[name] = ip
		}
	}
	for _, o := range obs {
		switch {
		case o.Collector == "azhaq-ports":
			var row struct{ Host, IP string }
			if json.Unmarshal(o.Payload, &row) == nil {
				set(row.Host, row.IP, true)
			}
		case o.Collector == "azhaq-http":
			var row struct{ URL, IP string }
			if json.Unmarshal(o.Payload, &row) == nil && row.IP != "" {
				if u, err := url.Parse(row.URL); err == nil {
					set(u.Hostname(), row.IP, true)
				}
			}
		case o.Kind == "dns":
			var row struct {
				FQDN     string   `json:"fqdn"`
				IPs      []string `json:"ips"`
				Wildcard bool     `json:"wildcard"`
			}
			if json.Unmarshal(o.Payload, &row) == nil && len(row.IPs) == 1 && !row.Wildcard {
				set(row.FQDN, row.IPs[0], false)
			}
		}
	}
	return out
}

// mergeListeners makes one service of each listener (address and port) and
// product: a name and its address are one listener, and the Server header
// and a page's technologies that name one product are one service, with the
// most specific version seen. The host is the same for every product of a
// listener (its first name, by order), and Names lists every host string the
// listener was reached by.
func mergeListeners(in []Service, addrs map[string]string) []Service {
	for i := range in {
		if in[i].IP == "" && normIP(in[i].Host) == "" {
			in[i].IP = addrs[strings.ToLower(in[i].Host)]
		}
	}
	names := map[string][]string{}
	for _, s := range in {
		if s.Host == "" {
			continue
		}
		l := s.Listener()
		if !slices.Contains(names[l], s.Host) {
			names[l] = append(names[l], s.Host)
		}
	}
	for l := range names {
		sort.Strings(names[l])
	}
	var out []Service
	at := map[string]int{}
	for _, s := range in {
		l := s.Listener()
		if ns := names[l]; len(ns) > 0 {
			s.Names = ns
			s.Host = firstName(ns)
		}
		k := l + "|" + ProductKey(s.Product)
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			out = append(out, s)
			continue
		}
		cur := out[i]
		win, lose := cur, s
		if moreSpecific(s.Version, cur.Version) {
			win, lose = s, cur
		}
		win.Origin = firstNonEmpty(win.Origin, lose.Origin)
		// A version that does not refine the winner is said, not dropped.
		for _, v := range append([]string{lose.Version}, lose.AlsoSeen...) {
			if !refines(win.Version, v) && !slices.Contains(win.AlsoSeen, v) {
				win.AlsoSeen = append(win.AlsoSeen, v)
			}
		}
		out[i] = win
	}
	return out
}

// refines says version a is b, or b with more said after it ("9.4.z-SNAPSHOT"
// of "9.4"): the same release named more exactly, not another one.
func refines(a, b string) bool {
	if a == b || sameVersion(a, b) {
		return true
	}
	return strings.HasPrefix(a, b) && len(a) > len(b) && !(a[len(b)] >= '0' && a[len(b)] <= '9')
}

// firstName is the host a listener's lead names: a name before an address.
func firstName(ns []string) string {
	for _, n := range ns {
		if normIP(n) == "" {
			return n
		}
	}
	return ns[0]
}

// moreSpecific says version a names a release more exactly than b: more
// parts ("9.4.z-SNAPSHOT" over "9.4"), then the longer text. Equal ones
// leave the first seen.
func moreSpecific(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	if pa != pb {
		return pa > pb
	}
	return len(a) > len(b)
}

func versionParts(v string) int {
	return len(strings.FieldsFunc(v, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}))
}
