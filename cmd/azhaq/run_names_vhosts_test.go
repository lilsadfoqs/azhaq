package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

const namesZone = "names.zz"

// namesLab is a domain served by a stub DNS and a web server that routes by
// Host: the names wiki, jenkins and grafana (in the built-in list, on no page
// and in no source) go to three apps on 127.0.0.2, an unknown Host gets a
// default page, and the zone has a wildcard that answers 127.0.0.9.
type namesLab struct {
	resolver string
	port     string
	mu       sync.Mutex
	hosts    []string // Hosts the web server was asked, with the path
}

func (l *namesLab) asked(host string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, h := range l.hosts {
		if strings.HasPrefix(h, host+" ") {
			n++
		}
	}
	return n
}

func newNamesLab(t *testing.T) *namesLab { return newNamesLabPages(t, nil) }

// newNamesLabPages is newNamesLab where the root page of a name in pages is the
// HTML given, header lines apart: its title and meta tags are the page's own.
func newNamesLabPages(t *testing.T, pages map[string]string) *namesLab {
	t.Helper()
	l := &namesLab{}
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no 127.0.0.2: %v", err)
	}
	apps := map[string]string{
		"wiki." + namesZone:    "Team wiki",
		"jenkins." + namesZone: "Build server",
		"grafana." + namesZone: "Dashboards",
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		l.mu.Lock()
		l.hosts = append(l.hosts, host+" "+r.URL.Path)
		l.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		title, ok := apps[host]
		switch {
		case pages[host] != "" && r.URL.Path == "/":
			fmt.Fprint(w, pages[host])
		case !ok:
			fmt.Fprint(w, "<html><head><title>It works</title></head><body>This is the default site of the server.</body></html>")
		case r.URL.Path == "/panel":
			fmt.Fprintf(w, "<html><head><title>%s panel</title></head><body>%s settings</body></html>", title, title)
		default:
			fmt.Fprintf(w, "<html><head><title>%s</title></head><body><h1>%s</h1><p>Welcome to %s, the part of the lab that does %s.</p><a href=\"/panel\">panel</a></body></html>", title, title, host, strings.ToLower(title))
		}
	})}}
	srv.Start()
	t.Cleanup(srv.Close)
	_, l.port, _ = net.SplitHostPort(ln.Addr().String())

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	dsrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		ip, ok := "", false
		switch {
		case apps[name] != "":
			ip, ok = "127.0.0.2", true
		case strings.HasSuffix(name, "."+namesZone):
			ip, ok = "127.0.0.9", true // the wildcard
		}
		switch {
		case !ok:
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			rr, _ := dns.NewRR(q.Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = dsrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = dsrv.Shutdown() })
	l.resolver = pc.LocalAddr().String()
	return l
}

func (l *namesLab) args(extra ...string) []string {
	return append([]string{"-domain", namesZone, "-cidr", "127.0.0.2/32", "-allow", namesZone, "-allow", "127.0.0.2",
		"-resolvers", l.resolver, "-ports", l.port, "-sources", "none", "-no-history"}, extra...)
}

// urlArgs map the service on the address as a URL given: no port is scanned and
// no web port names it, so a name reaches it only as a virtual host.
func (l *namesLab) urlArgs(extra ...string) []string {
	return append([]string{"-domain", namesZone, "-url", "http://127.0.0.2:" + l.port + "/", "-allow", namesZone, "-allow", "127.0.0.2",
		"-resolvers", l.resolver, "-sources", "none", "-no-history"}, extra...)
}

// visitedURLs are the visited URL rows of a run, by key, with their titles.
func visitedURLs(t *testing.T, out string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, r := range jsonRows(t, out) {
		if r["type"] == "URL" && r["coverage"] == "visited" {
			title, _ := r["title"].(string)
			got[r["key"].(string)] = title
		}
	}
	return got
}

// The default run guesses names from the list azhaq carries, asks them at the
// run's resolvers, and tries each name as a virtual host on the web service
// found on the address: the three apps are mapped by name, and so are the
// pages they link to. The wildcard's answers are not names.
func TestRunGuessesNamesAndMapsTheAppsByName(t *testing.T) {
	lab := newNamesLab(t)
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, append([]string{"run"}, lab.args("-db", "n.db")...)...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	rows := visitedURLs(t, out)
	for name, title := range map[string]string{"wiki": "Team wiki", "jenkins": "Build server", "grafana": "Dashboards"} {
		key := fmt.Sprintf("http://%s.%s:%s/", name, namesZone, lab.port)
		if rows[key] != title {
			t.Errorf("%s: want the app %q, rows %v", key, title, rows)
		}
		if _, ok := rows[strings.TrimSuffix(key, "/")+"/panel"]; !ok {
			t.Errorf("the page %spanel the app links to was not crawled by name: %v", key, rows)
		}
	}
	if def := rows[fmt.Sprintf("http://127.0.0.2:%s/", lab.port)]; def != "It works" {
		t.Errorf("the address's own default site: %q", def)
	}
	var names []string
	for _, r := range jsonRows(t, out) {
		if r["type"] == "Hostname" && r["role"] == "live" {
			names = append(names, r["key"].(string))
		}
	}
	if len(names) != 3 {
		t.Errorf("the wildcard's answers were counted as names: %v", names)
	}
	// one request for each (name, address, port): the default answer is
	// learned with two names that cannot exist, and each real name is asked once.
	for _, n := range []string{"wiki", "jenkins", "grafana"} {
		if got := lab.asked(n + "." + namesZone); got < 1 {
			t.Errorf("%s was never asked for", n)
		}
	}
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "answered like *."+namesZone+" (127.0.0.9)") {
		t.Errorf("the wildcard's answers are not said apart: %q", rep.Notes)
	}
}

// -dns-brute none turns the guessing off: no name is found, and the virtual
// host pass has no name to try.
func TestRunDNSBruteNoneAsksNoName(t *testing.T) {
	lab := newNamesLab(t)
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, append([]string{"run"}, lab.args("-dns-brute", "none", "-db", "none.db")...)...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	for k := range visitedURLs(t, out) {
		if strings.Contains(k, namesZone) {
			t.Errorf("a name was found with guessing off: %s", k)
		}
	}
	if n := lab.asked("wiki." + namesZone); n != 0 {
		t.Errorf("wiki was asked for %d times", n)
	}
}

// A service given as a URL, on a port no name is asked on, is tried with the
// names the guesses found: the three apps are mapped by name, and -no-vhost
// keeps the guesses and not those requests.
func TestRunTriesTheNamesFoundAsVirtualHostsOfAGivenService(t *testing.T) {
	lab := newNamesLab(t)
	t.Chdir(t.TempDir())
	out, rep, code := runContract(t, append([]string{"run"}, lab.urlArgs("-db", "v.db")...)...)
	if code != exitOK && code != exitPartial {
		t.Fatalf("exit %d: failed %+v notes %q", code, rep.Failed, rep.Notes)
	}
	rows := visitedURLs(t, out)
	for name, title := range map[string]string{"wiki": "Team wiki", "jenkins": "Build server", "grafana": "Dashboards"} {
		key := fmt.Sprintf("http://%s.%s:%s/", name, namesZone, lab.port)
		if rows[key] != title {
			t.Errorf("%s: want the app %q, rows %v", key, title, rows)
		}
		if _, ok := rows[key+"panel"]; !ok {
			t.Errorf("the page %spanel the app links to was not crawled by name: %v", key, rows)
		}
	}
	// the made-up names the default answer is learned with are two requests;
	// each name is asked once as a virtual host.
	if n := lab.asked("wiki." + namesZone); n < 1 {
		t.Errorf("wiki was never asked for")
	}

	t.Chdir(t.TempDir())
	out, _, _ = runContract(t, append([]string{"run"}, lab.urlArgs("-no-vhost", "-db", "nv.db")...)...)
	var names int
	for _, r := range jsonRows(t, out) {
		if r["type"] == "Hostname" && r["role"] == "live" {
			names++
		}
	}
	if names != 3 {
		t.Errorf("guesses found %d names, want 3", names)
	}
	for k := range visitedURLs(t, out) {
		if strings.Contains(k, namesZone) {
			t.Errorf("-no-vhost: %s was mapped by name", k)
		}
	}
}

// A file replaces the list: only its words are asked, and the plan counts them.
func TestRunDNSBruteFileReplacesTheList(t *testing.T) {
	lab := newNamesLab(t)
	t.Chdir(t.TempDir())
	words := wlist(t, "wiki", "nothing")
	out, _, _ := runContract(t, append([]string{"run"}, lab.args("-dns-brute", words, "-db", "f.db")...)...)
	var names []string
	for _, r := range jsonRows(t, out) {
		if r["type"] == "Hostname" && r["role"] == "live" {
			names = append(names, r["key"].(string))
		}
	}
	if len(names) != 1 || names[0] != "wiki."+namesZone {
		t.Errorf("names %v, want only wiki", names)
	}
}

// The plan shows the guesses and the virtual host requests, and a run with
// -dns-brute none or -no-vhost does not plan them.
func TestPlanShowsTheGuessesAndTheVhostRequests(t *testing.T) {
	lab := newNamesLab(t)
	t.Chdir(t.TempDir())
	text, _, _ := cli(t, append([]string{"plan"}, lab.args()...)...)
	for _, want := range []string{"5000 words of the built-in list", "5000 DNS queries", "virtual host requests"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan lacks %q:\n%s", want, text)
		}
	}
	st := planCost(t, lab.args()...)
	if got := stageAmount(st["names"], "estimate", "dns_queries"); got < 5000 {
		t.Errorf("the names stage counts %v queries, want the 5000 guesses at least", got)
	}
	if !strings.Contains(fmt.Sprint(st["web"]["not_counted"]), "virtual host requests") {
		t.Errorf("the web stage does not say what the virtual host requests are: %v", st["web"])
	}
	off, _, _ := cli(t, append([]string{"plan"}, lab.args("-dns-brute", "none", "-no-vhost")...)...)
	if strings.Contains(off, "built-in list") || strings.Contains(off, "virtual host requests") {
		t.Errorf("the plan still shows them:\n%s", off)
	}
}

// A run with no -allow, and -passive and -probe, guess nothing unless the flag
// asks: the built-in list needs a scope that names the domain.
func TestRunGuessesNeedAScopeAndSendNothingPassive(t *testing.T) {
	lab := newNamesLab(t)
	t.Chdir(t.TempDir())
	for _, extra := range [][]string{{"-passive"}, {"-probe"}} {
		text, _, _ := cli(t, append([]string{"plan"}, lab.args(extra...)...)...)
		if strings.Contains(text, "built-in list") || strings.Contains(text, "virtual host requests") {
			t.Errorf("%v: the plan guesses:\n%s", extra, text)
		}
	}
	text, _, _ := cli(t, "plan", "-domain", namesZone, "-resolvers", lab.resolver, "-sources", "none")
	if strings.Contains(text, "built-in list") {
		t.Errorf("no scope named, and the plan guesses:\n%s", text)
	}
}
