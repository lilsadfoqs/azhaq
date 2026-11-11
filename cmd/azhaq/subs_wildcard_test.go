package main

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// wildZone serves a zone whose every name has an A of 127.0.0.2, except the
// names in real, and answers NXDOMAIN outside it.
func wildZone(t *testing.T, zone string, real map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		ip, ok := real[name]
		switch {
		case !ok && strings.HasSuffix(name, "."+zone):
			ip, ok = "127.0.0.2", true
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
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// A guess only a wildcard answered is left out, and counted as a wildcard's
// answer, not as a name that did not resolve (#361).
func TestSubsLiveCountsAGuessOnlyAWildcardAnsweredApart(t *testing.T) {
	t.Chdir(t.TempDir())
	resolver := wildZone(t, "wild.lab.zz", map[string]string{"real.wild.lab.zz": "192.0.2.7"})
	defer subcol.UseTestSources()()
	words := wlist(t, "a1", "a2", "a3", "real", "zzz")
	out, rep, code := runContract(t, "subs", "-d", "wild.lab.zz", "-w", words, "-live", "-sources", "none", "-resolvers", resolver, "-no-history")
	if got := hosts(t, out); code != exitOK || len(got) != 1 || got[0] != "real.wild.lab.zz" {
		t.Fatalf("exit %d, printed %v", code, got)
	}
	if rep.Counts["asked by guessing"] != 5 || rep.Counts["wildcard answers left out"] != 4 || rep.Counts["did not resolve"] != 0 {
		t.Errorf("counts %v: 4 guesses got the wildcard's answer, none was NXDOMAIN", rep.Counts)
	}
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "4 names answered like *.wild.lab.zz (127.0.0.2)") {
		t.Errorf("notes %s", notes)
	}
}

// dns -w counts the wildcard's answers apart too.
func TestDNSWordsCountAWildcardAnswerApart(t *testing.T) {
	t.Chdir(t.TempDir())
	resolver := wildZone(t, "wild.lab.zz", map[string]string{"real.wild.lab.zz": "192.0.2.7"})
	ls, rep, _ := dnsOut(t, "-d", "wild.lab.zz", "-w", "a1,a2,real", "-r", resolver, "-json")
	if len(ls) != 1 || rep.Counts["wildcard answers left out"] != 2 || rep.Counts["did not resolve"] != 0 {
		t.Errorf("%v %v", ls, rep.Counts)
	}
}
