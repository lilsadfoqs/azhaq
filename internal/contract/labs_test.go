package contract

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Labs is what one row of a matrix runs against: a site, a proxy in front
// of it, counted ports, a resolver; each of them records what reaches it.
type Labs struct {
	T     *testing.T
	Dir   string
	Site  *Site
	Proxy *Proxy

	// Ports is the TCP lab and Resolver the DNS one, made when a row asks.
	Ports    *PortLab
	Resolver *Resolver

	results []Result
}

func newLabs(t *testing.T) *Labs {
	t.Helper()
	return &Labs{T: t, Dir: t.TempDir(), Site: newSite(t), Proxy: newProxy(t)}
}

// Allow is the scope that holds a run to the site.
func (l *Labs) Allow() string { return l.Site.Host() }

// Cmd runs the binary in the lab's directory under -json.
func (l *Labs) Cmd(args ...string) Result {
	l.T.Helper()
	// -json is the command's own flag: before the run options of roles and watch.
	if i := slices.Index(args, "--"); i >= 0 {
		args = slices.Insert(slices.Clone(args), i, "-json")
	} else {
		args = append(slices.Clone(args), "-json")
	}
	r := Run(l.T, l.Dir, args...)
	l.results = append(l.results, r)
	return r
}

// File writes a file in the lab's directory and returns its name.
func (l *Labs) File(name, body string) string {
	l.T.Helper()
	if err := os.WriteFile(filepath.Join(l.Dir, name), []byte(body), 0o644); err != nil {
		l.T.Fatal(err)
	}
	return name
}

// PortLab is TCP listeners that count each connection: one that closes at
// once, one that speaks first, one that answers HTTP, and a closed port.
type PortLab struct {
	Wire                       *Wire
	Closing, Banner, Web, Gone string // host:port
}

func newPortLab(t *testing.T) *PortLab {
	t.Helper()
	p := &PortLab{Wire: newWire()}
	p.Closing = listenCounted(t, p.Wire, nil).Addr
	p.Banner = listenCounted(t, p.Wire, func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	}).Addr
	p.Web = listenCounted(t, p.Wire, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 4096)
		if n, _ := c.Read(buf); n > 0 {
			_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nServer: lab\r\nContent-Type: text/html\r\n\r\n<title>x</title>"))
		}
	}).Addr
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no TCP: %v", err)
	}
	p.Gone = ln.Addr().String()
	ln.Close()
	return p
}

// Ports are the lab's port numbers, comma-joined, the closed one included.
func (p *PortLab) List() string {
	var ports []string
	for _, a := range []string{p.Closing, p.Banner, p.Web, p.Gone} {
		_, port, _ := net.SplitHostPort(a)
		ports = append(ports, port)
	}
	return strings.Join(ports, ",")
}

// Resolver is a DNS server that answers for the names of a zone and counts
// each packet it gets.
type Resolver struct {
	Addr string
	Wire *Wire
}

func newResolver(t *testing.T, domain string, hosts ...string) *Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	r := &Resolver{Addr: pc.LocalAddr().String(), Wire: newWire()}
	known := map[string]bool{}
	for _, h := range hosts {
		known[h+"."+domain] = true
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r.Wire.addUDP(r.Addr)
		m := new(dns.Msg)
		m.SetReply(q)
		name := strings.TrimSuffix(strings.ToLower(q.Question[0].Name), ".")
		switch {
		case known[name] && q.Question[0].Qtype == dns.TypeA:
			rr, _ := dns.NewRR(name + ". 60 IN A 127.0.0.9")
			m.Answer = append(m.Answer, rr)
		case known[name] || name == domain:
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return r
}

// har writes a history of one account's requests to the site.
func har(site *Site, entries ...[2]string) string {
	type kv struct{ Name, Value string }
	type req struct {
		Method  string `json:"method"`
		URL     string `json:"url"`
		Headers []kv   `json:"headers"`
		Post    *struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"postData,omitempty"`
	}
	var es []map[string]any
	for _, e := range entries {
		rq := req{Method: e[0], URL: site.URL + e[1], Headers: []kv{{"Authorization", "Bearer t-alice"}}}
		if e[0] != "GET" {
			rq.Headers = append(rq.Headers, kv{"Content-Type", "application/json"})
			rq.Post = &struct {
				MimeType string `json:"mimeType"`
				Text     string `json:"text"`
			}{"application/json", `{"name":"x"}`}
		}
		es = append(es, map[string]any{"request": rq, "response": map[string]any{"status": 200,
			"content": map[string]any{"mimeType": "application/json", "text": `{"owner":"alice"}`}}})
	}
	b, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": es}})
	return string(b)
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var _ = fmt.Sprint
