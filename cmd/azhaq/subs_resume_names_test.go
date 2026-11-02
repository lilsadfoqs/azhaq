package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/collectors/subcol"
)

// nxResolver answers api.example.org and nothing else exists.
func nxResolver(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if q := r.Question[0]; q.Name == "api.example.org." && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")})
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// A -live run the time limit stopped says the limit, not a failed lookup,
// and lists how to get the names it left; the resume that checks them all
// ends complete: exit 0 and no failed source. The names the stopped run had
// not asked are not called dead in the map: their row says they were not checked.
func TestSubsLiveStoppedByTimeLimitThenResumedClean(t *testing.T) {
	defer subcol.UseTestSources(subcol.TestSource{Name: "history", Default: true})()
	t.Chdir(t.TempDir())
	dir, _ := dataDirs.LoadOrStore(t.Name(), t.TempDir())
	hist := map[string]map[string]any{"api.example.org": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}}
	for i := 0; i < 120; i++ {
		hist[fmt.Sprintf("h%d.example.org", i)] = map[string]any{"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}
	}
	raw, _ := json.Marshal(hist)
	if err := os.MkdirAll(filepath.Join(dir.(string), "names"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.(string), "names", "example.org.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	resolver := nxResolver(t)

	_, rep, code := runContract(t, "subs", "-d", "example.org", "-live", "-resolvers", resolver, "-dns-rate", "20", "-max-time", "3s", "-db", "c.db")
	if code != exitLimit {
		t.Fatalf("stopped run: exit %d\n%+v", code, rep)
	}
	var said bool
	for _, f := range rep.Failed {
		if strings.Contains(f.Error, "lookups failed") {
			t.Errorf("a run the limit stopped says the lookups failed: %+v", f)
		}
		said = said || strings.Contains(f.Error, "time limit")
	}
	if !said {
		t.Errorf("the failed source does not name the limit: %+v", rep.Failed)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "azhaq resume -db c.db checks them") || !strings.Contains(notes, "-role unresolved lists them") {
		t.Errorf("the summary does not say how to check and list the names left: %s", notes)
	}
	if !strings.Contains(notes, "name history ") || !strings.Contains(notes, " names read, ") {
		t.Errorf("the summary does not say the name history was used: %s", notes)
	}
	out, _, _ := runContract(t, "query", "-db", "c.db", "-type", "Hostname", "-role", "unresolved")
	if !strings.Contains(out, `"proof":"not checked: `) {
		t.Errorf("the names left carry no mark that they were not checked:\n%s", out)
	}

	_, rep, code = runContract(t, "resume", "-db", "c.db", "-resolvers", resolver, "-dns-rate", "0")
	if code != exitOK || len(rep.Failed) != 0 {
		t.Errorf("the resume that checked every name: exit %d, failed %+v", code, rep.Failed)
	}
}
