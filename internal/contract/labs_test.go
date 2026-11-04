package contract

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Labs is what one row of a matrix runs against: a site, a proxy in front
// of it, counted ports, a resolver; each of them records what reaches it.
type Labs struct {
	T     *testing.T
	Dir   string
	Site  *Site
	Proxy *Proxy
	Other *Site // a second site, outside the scope

	// Ports is the TCP lab and Resolver the DNS one, made when a row asks.
	Ports    *PortLab
	UDP      string // a counted UDP port beside Ports
	Resolver *Resolver

	results []Result
	env     Env // set by a row's shape, for its run
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
	v := newInv(l.T, "")
	checkSummary(v, r)
	v.Done()
	return r
}

func lookChrome() (string, error) {
	if p, err := exec.LookPath("google-chrome"); err == nil {
		return p, nil
	}
	return exec.LookPath("chromium")
}

// Chrome is Cmd for a command that starts Chrome: the test is skipped where
// there is none or it will not start (a sandbox the machine does not give).
func (l *Labs) Chrome(args ...string) Result {
	l.T.Helper()
	if _, err := exec.LookPath("google-chrome"); err != nil {
		if _, err := exec.LookPath("chromium"); err != nil {
			l.T.Skip("no Chrome on this machine")
		}
	}
	args = append(slices.Clone(args), "-json")
	r := RunRaw(l.T, l.Dir, nil, args...)
	if !r.Has || r.Code == 1 || strings.Contains(r.Stderr, "sandbox") {
		l.T.Skipf("Chrome did not start here: %s", strings.TrimSpace(r.Stderr))
	}
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
	Wire *Wire
	// Asked is the HTTP requests the web port was sent, by method and URL:
	// the requests a logging server in front of the port counts. They are
	// bytes written on a connection Wire counts, so Wire.Total leaves them out.
	Asked                      *Wire
	Closing, Banner, Web, Gone string // host:port
	goneAsked                  bool
}

func newPortLab(t *testing.T) *PortLab {
	t.Helper()
	p := &PortLab{Wire: newWire(), Asked: newWire()}
	p.Closing = listenCounted(t, p.Wire, nil).Addr
	p.Banner = listenCounted(t, p.Wire, func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	}).Addr
	p.Web = listenCounted(t, p.Wire, func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			p.Asked.addHTTP(req.Method, "http://"+c.LocalAddr().String()+req.URL.RequestURI())
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
	p.goneAsked = true
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

// listenUDP is a UDP port that counts each packet and answers none.
func listenUDP(t testing.TB, wire *Wire) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	addr := pc.LocalAddr().String()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			wire.addUDP(addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return addr
}
