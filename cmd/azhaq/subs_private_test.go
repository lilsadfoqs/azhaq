package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// A name whose answers are all loopback, private or link-local is marked
// private_answer and counted apart; a public name carries no mark.
func TestSubsLiveMarksAPrivateAnswer(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	zone := map[string]string{"localhost.pub.example": "127.0.0.1", "intra.pub.example": "10.1.2.3", "www.pub.example": "192.0.2.7"}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		ip, ok := zone[strings.TrimSuffix(strings.ToLower(q.Name), ".")]
		switch {
		case !ok:
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			rr, _ := dns.NewRR(q.Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	defer subcol.UseTestSources()()
	words := wlist(t, "localhost", "intra", "www", "zzz")
	out, rep, _ := runContract(t, "subs", "-d", "pub.example", "-sources", "none", "-live", "-w", words, "-resolvers", pc.LocalAddr().String(), "-no-history")
	private := map[string]bool{}
	for _, l := range lines(out) {
		var row struct {
			Host    string `json:"host"`
			Private bool   `json:"private_answer"`
		}
		if err := json.Unmarshal([]byte(l), &row); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		private[row.Host] = row.Private
	}
	if len(private) != 3 || !private["localhost.pub.example"] || !private["intra.pub.example"] || private["www.pub.example"] {
		t.Errorf("private_answer by name: %v, want the loopback and the 10/8 name marked, the public one not", private)
	}
	if rep.Counts["private answers"] != 2 {
		t.Errorf("counts %v, want 2 private answers", rep.Counts)
	}
}
