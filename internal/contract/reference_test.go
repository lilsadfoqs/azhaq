//go:build reference

package contract

import (
	"encoding/xml"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

// The reference matrix: each fixture is a small server shaped like a real
// case, and azhaq's default output must be at least what the reference tool
// gives for it (curl, nmap -sV, katana), so a parity regression fails here
// before anyone compares by hand. It runs where the tools are installed:
//
//	go test -tags reference ./internal/contract -run TestReference
//
// A tool that is not installed skips the rows that need it.

type nmapService struct {
	Name, Product, Version, Tunnel string
}

// nmapServes is what nmap -sV says about one port of 127.0.0.1.
func nmapServes(t *testing.T, port, limit string) (nmapService, bool) {
	t.Helper()
	lookTool(t, "nmap")
	out := output(t, "nmap", "-sV", "-n", "-Pn", "--host-timeout", limit, "-p", port, "127.0.0.1", "-oX", "-")
	var doc struct {
		Ports []struct {
			State struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
				Tunnel  string `xml:"tunnel,attr"`
			} `xml:"service"`
		} `xml:"host>ports>port"`
	}
	if err := xml.Unmarshal([]byte(out), &doc); err != nil || len(doc.Ports) == 0 || doc.Ports[0].State.State != "open" {
		t.Logf("nmap gave no answer for port %s in %s: no comparison with it", port, limit)
		return nmapService{}, false
	}
	p := doc.Ports[0]
	return nmapService{p.Service.Name, p.Service.Product, p.Service.Version, p.Service.Tunnel}, true
}

// azhaqServes is the row azhaq ports gives for one port, by default.
func azhaqServes(t *testing.T, dir, port string) map[string]any {
	t.Helper()
	r := Run(t, dir, "ports", "-host", "127.0.0.1", "-p", port, "-allow", "127.0.0.1", "-json")
	rows := r.Rows(t)
	if len(rows) == 0 {
		t.Fatalf("ports printed no row for the open port %s", port)
	}
	return rows[0]
}

func str(row map[string]any, k string) string { s, _ := row[k].(string); return s }

// atLeastNmap fails for each thing nmap says about the port that azhaq does not.
func atLeastNmap(v *Inv, n nmapService, row map[string]any) {
	named := func(s string) bool { return s != "" && s != "unknown" && s != "tcpwrapped" }
	if named(n.Name) && !named(str(row, "service")) {
		v.Errorf("nmap names the service %q (product %q, version %q); azhaq names none", n.Name, n.Product, n.Version)
	}
	if n.Product != "" && str(row, "product") == "" {
		v.Errorf("nmap gives the product %q; azhaq gives none", n.Product)
	}
	if n.Version != "" && str(row, "version") == "" {
		v.Errorf("nmap gives the version %q; azhaq gives none", n.Version)
	}
	if n.Tunnel == "ssl" && row["tls"] != true {
		v.Errorf("nmap sees TLS on the port; azhaq does not")
	}
}

func TestReferenceTLSHandshakeClasses(t *testing.T) {
	lookTool(t, "curl")
	for _, c := range tlsClasses {
		t.Run(c.name, func(t *testing.T) {
			known := ""
			if c.name == "tls12-rsa-kex" || c.name == "tls12-dhe" {
				known = ""
			}
			// Go serves the two classes it offers, side by side; openssl the other two, one connection at a time.
			var addr string
			nmapToo := false
			switch c.name {
			case "tls12-ecdhe":
				addr, nmapToo = goTLSServer(t, false), true
			case "tls13":
				addr, nmapToo = goTLSServer(t, true), true
			default:
				addr = opensslServer(t, c)
			}
			if got := strings.TrimSpace(output(t, "curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", "https://"+addr+"/")); got != "200" {
				t.Skipf("curl does not complete this class (%q): there is no reference to match", got)
			}
			dir := t.TempDir()
			v := newInv(t, known)
			// curl completes it: probe and crawl must too.
			p := RunRaw(t, dir, nil, "probe", "-u", "https://"+addr+"/", "-allow", "127.0.0.1", "-json")
			if rows := p.Rows(t); p.Code != 0 || len(rows) == 0 || rows[0]["failed"] == true || rows[0]["status_code"] != float64(200) {
				v.Errorf("probe: exit %d; curl gets 200\n%s", p.Code, p.Stdout)
			}
			cr := RunRaw(t, dir, nil, "crawl", "-u", "https://"+addr+"/", "-allow", "127.0.0.1", "-json")
			if cr.Code != 0 {
				v.Errorf("crawl: exit %d; curl gets 200: %s", cr.Code, failureListed(cr.Summary))
			}
			// curl completed the handshake, so ports must see TLS on the port.
			row := azhaqServes(t, dir, portOf(addr))
			if row["tls"] != true {
				v.Errorf("curl completes a TLS handshake on the port; ports says tls %v", row["tls"])
			}
			// nmap -sV names it ssl/http: ports must name it too. (An openssl s_server serves
			// one connection at a time, and nmap's probes wait on each other there.)
			if nmapToo {
				if n, ok := nmapServes(t, portOf(addr), "30s"); ok {
					atLeastNmap(v, n, row)
				}
			}
			v.Done()
		})
	}
}

func TestReferenceServicesByTheirFirstBytes(t *testing.T) {
	for _, c := range []struct {
		name, known string
		start       func(*testing.T) string
	}{
		// #100 describes this service on port 50000; on another port azhaq already names it.
		{"a service that answers only GET", "", getOnly},
		{"JDWP", "", jdwp},
		{"Java RMI registry", "", rmi},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr := c.start(t)
			v := newInv(t, c.known)
			row := azhaqServes(t, t.TempDir(), portOf(addr))
			n, ok := nmapServes(t, portOf(addr), "180s")
			if !ok {
				t.Skip("nmap does not name this service here: there is no reference to match")
			}
			atLeastNmap(v, n, row)
			v.Done()
		})
	}
}

// katanaFinds is the same-origin paths katana lists for a site.
func katanaFinds(t *testing.T, site string) map[string]bool {
	t.Helper()
	lookTool(t, "katana")
	out := output(t, "katana", "-u", site, "-d", "3", "-jc", "-jsl", "-silent", "-nc", "-timeout", "10", "-c", "10")
	return pathsOf(site, lines0(out))
}

func pathsOf(site string, urls []string) map[string]bool {
	base, _ := url.Parse(site)
	out := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(strings.Fields(raw + " ")[0])
		if err != nil || u.Host != base.Host {
			continue
		}
		path := u.Path
		if path == "" {
			path = "/" // http://host and http://host/ are one page
		}
		key := path
		if u.RawQuery != "" { // an empty query is no query: "/a?" is "/a"
			key += "?" + u.RawQuery
		}
		out[key] = true
	}
	return out
}

func TestReferenceCrawlListsWhatKatanaDoes(t *testing.T) {
	_, err := exec.LookPath("katana")
	if err != nil {
		t.Skip("no katana on this machine: the reference comparison runs where it is installed")
	}
	for _, c := range []struct {
		name, known string
		site        func(*testing.T) *Site
		// not are paths the reference lists that are no routes (see the issue the marker names).
		not []string
		// parents are paths listed whole that are no routes: /api/v1 is the parent of the one real
		// route /api/v1/dashboards, and the site answers it 404.
		parents []string
	}{
		{"a page that loads a stylesheet, a script and an image", "", func(t *testing.T) *Site { return newSite(t) }, nil, nil},
		{"a single-page app with a webpack module map", "", webpackSite, []string{"/components/locale/", "/AdhocFilter", "/AdhocMetric"}, []string{"/api/v1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			site := c.site(t)
			want := katanaFinds(t, site.URL)
			r := RunRaw(t, t.TempDir(), nil, "crawl", "-u", site.URL, "-depth", "3", "-silent", "-hints")
			got := pathsOf(site.URL, lines0(r.Stdout))
			v := newInv(t, c.known)
			for p := range want {
				skip := false
				for _, n := range c.not {
					skip = skip || strings.Contains(p, n)
				}
				for _, n := range c.parents {
					skip = skip || p == n
				}
				if !skip && !got[p] {
					v.Errorf("katana lists %s; azhaq does not", p)
				}
			}
			v.Done()
		})
	}
}
