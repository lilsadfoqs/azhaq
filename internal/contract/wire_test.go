package contract

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Wire is what a recorder saw arrive: the multiset of "METHOD URL" lines of
// HTTP requests, and the TCP connections and UDP packets by "host:port".
type Wire struct {
	mu   sync.Mutex
	http map[string]int
	tcp  map[string]int
	udp  map[string]int
}

func newWire() *Wire {
	return &Wire{http: map[string]int{}, tcp: map[string]int{}, udp: map[string]int{}}
}

// canon is the form a request is compared in: the URL without fragment and
// userinfo, an empty path as "/".
func canon(method, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return method + " " + raw
	}
	u.Fragment, u.User = "", nil
	if u.Path == "" {
		u.Path = "/"
	}
	return method + " " + u.String()
}

func (w *Wire) addHTTP(method, raw string) {
	w.mu.Lock()
	w.http[canon(method, raw)]++
	w.mu.Unlock()
}

// Reset forgets what was seen.
func (w *Wire) Reset() {
	w.mu.Lock()
	w.http, w.tcp, w.udp = map[string]int{}, map[string]int{}, map[string]int{}
	w.mu.Unlock()
}

func (w *Wire) addTCP(addr string) { w.mu.Lock(); w.tcp[addr]++; w.mu.Unlock() }
func (w *Wire) addUDP(addr string) { w.mu.Lock(); w.udp[addr]++; w.mu.Unlock() }

// Total is every request, connection and packet seen.
func (w *Wire) Total() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, m := range []map[string]int{w.http, w.tcp, w.udp} {
		for _, c := range m {
			n += c
		}
	}
	return n
}

func (w *Wire) snapshot(m map[string]int) map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]int{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// diff says how two multisets differ, "" when they are equal.
func diff(aName string, a map[string]int, bName string, b map[string]int) string {
	var out []string
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		if a[k] != b[k] {
			out = append(out, fmt.Sprintf("  %s: %s %d, %s %d", k, aName, a[k], bName, b[k]))
		}
	}
	if len(out) > 12 {
		out = append(out[:12], fmt.Sprintf("  … and %d more", len(out)-12))
	}
	return strings.Join(out, "\n")
}

// Proxy is a forward proxy that records every request it is given and sends
// it on. A CONNECT is recorded by its host:port.
type Proxy struct {
	URL  string
	Wire *Wire
	ln   net.Listener
}

func newProxy(t testing.TB) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no TCP: %v", err)
	}
	p := &Proxy{URL: "http://" + ln.Addr().String(), Wire: newWire(), ln: ln}
	tr := &http.Transport{Proxy: nil, DisableCompression: true}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.Wire.addHTTP("CONNECT", "//"+r.Host)
			tunnel(w, r)
			return
		}
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		p.Wire.addHTTP(r.Method, r.URL.String())
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := tr.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); tr.CloseIdleConnections() })
	return p
}

func tunnel(w http.ResponseWriter, r *http.Request) {
	up, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		return
	}
	c, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() { _, _ = io.Copy(up, c); up.Close() }()
	go func() { _, _ = io.Copy(c, up); c.Close() }()
}

// Counted is a TCP listener that counts each connection it accepts, then
// hands it to serve (nil: closes it at once).
type Counted struct {
	Addr string
	Wire *Wire
	ln   net.Listener
}

func listenCounted(t testing.TB, wire *Wire, serve func(net.Conn)) *Counted {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no TCP: %v", err)
	}
	c := &Counted{Addr: ln.Addr().String(), Wire: wire, ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wire.addTCP(c.Addr)
			if serve == nil {
				conn.Close()
				continue
			}
			go serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

// ledgerLine is the part of a ledger line the invariants read.
type ledgerLine struct {
	Kind   string `json:"kind"`
	Class  string `json:"class"`
	Method string `json:"method"`
	Target string `json:"target"`
	Host   string `json:"host"`
}

func (l ledgerLine) toTarget() bool {
	return l.Kind != "seal" && (l.Class == "" || l.Class == "target")
}

// readLedger reads every line of a ledger file.
func readLedger(t testing.TB, path string) []ledgerLine {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("no ledger: %v", err)
	}
	defer f.Close()
	var out []ledgerLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var l ledgerLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("ledger line is not JSON: %q", sc.Text())
		}
		out = append(out, l)
	}
	return out
}

// Sent is what a ledger lists as sent to targets: HTTP and Chrome lines as
// "METHOD URL", TCP and UDP lines by address, and the count of all.
type Sent struct {
	HTTP, TCP, UDP map[string]int
	N              int
}

func ledgerSent(lines []ledgerLine) Sent {
	s := Sent{HTTP: map[string]int{}, TCP: map[string]int{}, UDP: map[string]int{}}
	for _, l := range lines {
		if !l.toTarget() {
			continue
		}
		s.N++
		switch l.Kind {
		case "http", "chrome":
			s.HTTP[canon(l.Method, l.Target)]++
		case "tcp":
			s.TCP[l.Target]++
		case "udp":
			s.UDP[l.Target]++
		}
	}
	return s
}
