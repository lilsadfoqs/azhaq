package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// spyZone is a resolver that records every name it is asked, with the types.
type spyZone struct {
	mu    sync.Mutex
	names []string
	addr  string
}

func (z *spyZone) asked(suffix string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	var out []string
	for _, n := range z.names {
		if strings.HasSuffix(n, suffix) {
			out = append(out, n)
		}
	}
	return out
}

// startSpyZone answers dangling.example.org with a CNAME to a name that does
// not exist, and 127.0.0.1 for the other names of example.org.
func startSpyZone(t *testing.T) *spyZone {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	z := &spyZone{addr: pc.LocalAddr().String()}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		z.mu.Lock()
		z.names = append(z.names, name)
		z.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		switch {
		case name == "dangling.example.org":
			rr, _ := dns.NewRR("dangling.example.org. 60 IN CNAME app.gone-co.com.")
			m.Answer = append(m.Answer, rr)
			m.Rcode = dns.RcodeNameError
		case strings.HasSuffix(name, ".example.org") && q.Qtype == dns.TypeA && !strings.HasPrefix(name, "zz"):
			rr, _ := dns.NewRR(q.Name + " 60 IN A 127.0.0.1")
			m.Answer = append(m.Answer, rr)
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return z
}

// A run asks about no name outside the scope it was given: the CNAME target
// of a dangling name is not looked up by the takeover check, and says so.
func TestRunNeverLooksUpACNAMETargetOutsideTheScope(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	z := startSpyZone(t)
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte("dangling\nwww\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, rep, _ := runContract(t, "run", "-domain", "example.org", "-allow", "example.org", "-sources", "none", "-dns-brute", words,
		"-resolvers", z.addr, "-dns-rate", "0", "-no-paths", "-depth", "3", "-no-history", "-db", "s.db", "-web-ports", "65534",
		"-no-favicon", "-no-tech", "-no-follow")
	if got := z.asked("gone-co.com"); len(got) != 0 {
		t.Errorf("names outside the scope were asked: %v", got)
	}
	if n := strings.Join(rep.Notes, "\n"); !strings.Contains(n, "not asked: 1 CNAME target on a domain outside the scope (gone-co.com)") {
		t.Errorf("the summary does not say the target was not asked: %v", rep.Notes)
	}
}

// A redirect to a name outside the scope is not followed, and the name is not
// looked up either.
func TestRunNeverLooksUpARedirectTargetOutsideTheScope(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	z := startSpyZone(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere-co.com/", http.StatusFound)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	runContract(t, "run", "-url", fmt.Sprintf("http://www.example.org:%s/", port), "-allow", "example.org", "-sources", "none",
		"-resolvers", z.addr, "-dns-rate", "0", "-no-paths", "-depth", "1", "-no-history", "-db", "r.db")
	if got := z.asked("elsewhere-co.com"); len(got) != 0 {
		t.Errorf("the redirect target was looked up: %v", got)
	}
}
