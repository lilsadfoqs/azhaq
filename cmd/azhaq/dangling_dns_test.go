package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// danglingLab is a resolver for a zone with a CNAME to a name on a provider's
// list (gone.azurewebsites.net), one to a name on no list
// (x.cloudprovider.example), one to the owner's own missing name, one whose
// target resolves, and one a wildcard (not a name) answers; every target but
// the live one answers NXDOMAIN.
func danglingLab(t *testing.T) (resolver string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	cname := map[string]string{
		"shop.example.org.": "gone.azurewebsites.net.",
		"old.example.org.":  "x.cloudprovider.example.",
		"own.example.org.":  "missing.example.org.",
		"live.example.org.": "up.example.net.",
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		rr := func(s string) dns.RR { x, _ := dns.NewRR(s); return x }
		switch target, ok := cname[q.Name]; {
		case q.Name == "up.example.net.":
			if q.Qtype == dns.TypeA {
				m.Answer = []dns.RR{rr("up.example.net. 60 IN A 192.0.2.7")}
			}
		case ok && q.Name == "live.example.org.":
			m.Answer = []dns.RR{rr(q.Name + " 60 IN CNAME " + target)}
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, rr("up.example.net. 60 IN A 192.0.2.7"))
			}
		case ok && q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{rr(q.Name + " 60 IN CNAME " + target)}
			m.Rcode = dns.RcodeNameError
		case ok && q.Qtype == dns.TypeCNAME:
			m.Answer = []dns.RR{rr(q.Name + " 60 IN CNAME " + target)}
		case ok:
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, l := range lines(out) {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			rows = append(rows, m)
		}
	}
	return rows
}

// A CNAME to a name that answered NXDOMAIN is a dangling-dns finding of what
// was measured (the chain, the answer, the resolver and a dig command), with
// or without the target on a provider list; the takeover stays a separate
// lead, and the owner's own name, a live target and a name with no CNAME are
// none. The finding is in report -findings, export -format findings, and the
// default hunt ranks it among the findings, before every lead.
func TestDanglingDNSFindingAndTakeoverLead(t *testing.T) {
	res := danglingLab(t)
	db := filepath.Join(t.TempDir(), "w.db")
	t.Chdir(t.TempDir())
	ls, _, code := dnsOut(t, "-d", "shop.example.org,old.example.org,own.example.org,live.example.org,www.example.org", "-r", res, "-db", db, "-json")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	// The name's row carries the measurement, with or without a takeover entry.
	rows := dnsRows(t, ls)
	if d, _ := rows["old.example.org"]["dangling"].(map[string]any); d["target"] != "x.cloudprovider.example" || d["rcode"] != "NXDOMAIN" || d["server"] != res || rows["old.example.org"]["takeover"] != nil {
		t.Errorf("old row %v", rows["old.example.org"])
	}
	for _, h := range []string{"own.example.org", "live.example.org", "www.example.org"} {
		if rows[h]["dangling"] != nil {
			t.Errorf("%s is not dangling: %v", h, rows[h])
		}
	}
	out, _, err := captureBoth(t, func() error {
		return run([]string{"report", "-findings", "-db", db, "-format", "jsonl"})
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	leads := map[string]map[string]any{}
	for _, r := range jsonLines(t, out) {
		host, _ := r["host"].(string)
		switch {
		case r["type"] == "finding" && r["kind"] == "dangling-dns":
			got[host] = r
		case r["type"] == "lead" && r["kind"] == "takeover":
			leads[host] = r
		case r["kind"] == "takeover" && r["type"] == "finding":
			t.Errorf("a takeover finding: %v", r)
		}
	}
	if len(got) != 2 || got["shop.example.org"] == nil || got["old.example.org"] == nil {
		t.Fatalf("dangling-dns findings %v, want shop and old only", got)
	}
	f := got["old.example.org"]
	dig, _ := f["reproduce"].(string)
	ev, _ := f["evidence"].(string)
	if f["severity"] != "low" || f["tier"] != "finding" || f["label"] != "proved" || f["excerpt_part"] != "dns" ||
		!strings.Contains(ev, "x.cloudprovider.example answered NXDOMAIN from "+res) || !strings.HasPrefix(dig, "dig @127.0.0.1 -p ") || !strings.Contains(dig, "A 'old.example.org'") {
		t.Errorf("finding %v", f)
	}
	if leads["shop.example.org"] == nil || leads["old.example.org"] != nil {
		t.Errorf("takeover leads %v: only the name on a provider's list has one", leads)
	}
	if l := leads["shop.example.org"]; l != nil && !strings.Contains(l["check"].(string), "claim the name at Azure") {
		t.Errorf("lead %v", l)
	}
	// export -format findings holds it too.
	exp, _, err := captureBoth(t, func() error {
		return run([]string{"export", "-db", db, "-format", "findings"})
	})
	if err != nil || strings.Count(exp, `"kind":"dangling-dns"`) != 2 {
		t.Errorf("export (%v): %s", err, exp)
	}
	// The default hunt lists the findings before every lead.
	hout, _, err := captureBoth(t, func() error { return cmdHunt([]string{"-db", db, "-json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var seenLead bool
	var found []string
	for _, r := range jsonLines(t, hout) {
		if r["type"] == "summary" {
			continue
		}
		if r["tier"] == "lead" {
			seenLead = true
		}
		if r["tier"] == "finding" {
			if seenLead {
				t.Errorf("a finding after a lead: %v", r)
			}
			if reasons, _ := r["reasons"].([]any); len(reasons) > 0 && reasons[0].(map[string]any)["signal"] == "dangling-dns" {
				found = append(found, r["key"].(string))
			}
		}
	}
	if strings.Join(found, ",") != "old.example.org,shop.example.org" && strings.Join(found, ",") != "shop.example.org,old.example.org" {
		t.Errorf("hunt's dangling-dns rows %v\n%s", found, hout)
	}
}

// -no-takeover turns the extra question off, not the measurement: with A asked the
// answer already ends at the name that did not exist, and the row says so;
// -cname alone has no answer that follows the chain, so it has none.
func TestDanglingStandsUnderNoTakeover(t *testing.T) {
	res := danglingLab(t)
	ls, _, code := dnsOut(t, "-d", "shop.example.org", "-r", res, "-no-takeover", "-json")
	row := dnsRows(t, ls)["shop.example.org"]
	if d, _ := row["dangling"].(map[string]any); code != exitOK || d["target"] != "gone.azurewebsites.net" || row["takeover"] != nil {
		t.Errorf("exit %d row %v", code, row)
	}
	ls, _, _ = dnsOut(t, "-d", "shop.example.org", "-r", res, "-cname", "-no-takeover", "-json")
	if row := dnsRows(t, ls)["shop.example.org"]; row["dangling"] != nil || row["cname_status"] != nil {
		t.Errorf("-cname alone asks nothing more: %v", row)
	}
	// With the question, -cname alone gets the measurement too.
	ls, _, _ = dnsOut(t, "-d", "old.example.org", "-r", res, "-cname", "-json")
	if row := dnsRows(t, ls)["old.example.org"]; row["dangling"] == nil || row["cname_status"] != "NXDOMAIN" {
		t.Errorf("-cname: %v", row)
	}
}
