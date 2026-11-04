package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/lilsadfoqs/azhaq/internal/ledger"
)

// typeLab is the dns lab with a count of the questions by type.
type typeLab struct {
	*dnsLab
	mu     sync.Mutex
	byType map[string]int
}

func startTypeLab(t *testing.T) *typeLab {
	t.Helper()
	lab := &dnsLab{}
	tl := &typeLab{dnsLab: lab, byType: map[string]int{}}
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; ; i++ {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Skipf("no UDP: %v", err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close()
		if i == 20 {
			t.Skipf("no TCP: %v", err)
		}
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		tl.mu.Lock()
		tl.byType[dns.TypeToString[r.Question[0].Qtype]]++
		tl.mu.Unlock()
		lab.handle(w, r)
	})
	us, ts := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: ln, Handler: h}
	go func() { _ = us.ActivateAndServe() }()
	go func() { _ = ts.ActivateAndServe() }()
	t.Cleanup(func() { _ = us.Shutdown(); _ = ts.Shutdown() })
	lab.addr = pc.LocalAddr().String()
	return tl
}

func (tl *typeLab) types() []string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	var out []string
	for k := range tl.byType {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (tl *typeLab) reset() {
	tl.mu.Lock()
	tl.byType = map[string]int{}
	tl.mu.Unlock()
}

func addLabNames(t *testing.T, add map[string][]string) {
	t.Helper()
	labZoneMu.Lock()
	for k, v := range add {
		labZone[k] = v
	}
	labZoneMu.Unlock()
	t.Cleanup(func() {
		labZoneMu.Lock()
		for k := range add {
			delete(labZone, k)
		}
		labZoneMu.Unlock()
	})
}

// dns neither reads nor writes the name history, and stores nothing outside
// -db: with a data directory of its own and no -db, nothing is created in it
// or beside the run.
func TestDNSStoresNothingOutsideDBAndKeepsNoNameHistory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	data := t.TempDir()
	t.Setenv("AZHAQ_DATA_DIR", data)
	lab := startLab(t)
	if _, _, code := dnsOut(t, "-l", writeList(t, "www.lab.zz", "api.lab.zz", "nope.lab.zz"), "-r", lab.addr, "-silent"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if left, _ := filepath.Glob(filepath.Join(data, "*")); len(left) != 0 {
		t.Errorf("dns wrote %v into the data directory", left)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("dns without -db left %v in the working directory", left)
	}
	// A history that is there is not read: a name only it holds is not asked.
	if err := os.MkdirAll(filepath.Join(data, "names"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "names", "lab.zz.json"), []byte(`{"www.lab.zz": {"first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(data, "names", "lab.zz.json"))
	lab.asked.Store(0)
	ls, rep, _ := dnsOut(t, "-d", "nope.lab.zz", "-r", lab.addr, "-json")
	if len(ls) != 0 || rep.Counts["asked"] != 1 {
		t.Errorf("rows %v, counts %v: dns asks the names it is given", ls, rep.Counts)
	}
	if after, _ := os.ReadFile(filepath.Join(data, "names", "lab.zz.json")); string(before) != string(after) {
		t.Errorf("dns changed the history file")
	}
}

// dns sends DNS queries and nothing else: the ledger of the run has DNS lines
// only and the summary counts no request.
func TestDNSSendsDNSQueriesAndNothingElse(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	_, rep, code := dnsOut(t, "-l", writeList(t, "www.lab.zz", "api.lab.zz", "nope.lab.zz", "x.wild.lab.zz"), "-r", lab.addr, "-all", "-json", "-ledger", "l.jsonl")
	if code != exitOK || rep.Requests != 0 {
		t.Fatalf("exit %d, requests %d", code, rep.Requests)
	}
	got := map[string]int{}
	if err := ledger.Read("l.jsonl", func(e ledger.Entry) error {
		if e.Kind != ledger.KindSeal {
			got[e.Kind+"/"+e.Class]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["dns/dns"] == 0 {
		t.Errorf("the ledger holds %v: want DNS lines only", got)
	}
}

// When a line is a record the summary counts records and names: with -resp-only
// and with a zone transfer as with -resp.
func TestDNSSummaryCountsRecordsOfNamesForEveryRecordForm(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	addLabNames(t, map[string][]string{"two.lab.zz.": {"A 192.0.2.7", "A 192.0.2.8"}, "one.lab.zz.": {"A 192.0.2.9"}})
	l := writeList(t, "two.lab.zz", "one.lab.zz")
	for _, form := range []string{"-resp", "-resp-only"} {
		out, errOut, err := captureBoth(t, func() error { return run([]string{"dns", "-l", l, "-r", lab.addr, "-a", form}) })
		if err != nil || len(lines(out)) != 3 || !strings.Contains(errOut, "3 records of 2 names") {
			t.Errorf("%s: %v, %d lines, summary %q", form, err, len(lines(out)), errOut)
		}
	}
	out, errOut, err := captureBoth(t, func() error {
		return run([]string{"dns", "-d", "lab.zz", "-r", lab.addr, "-axfr", "-allow", "lab.zz", "-allow", "127.0.0.1", "-timeout", "300ms"})
	})
	if err != nil || !strings.Contains(errOut, fmt.Sprintf("%d records of 1 name (", len(lines(out)))) {
		t.Errorf("a transfer: %v, %d lines, summary %q", err, len(lines(out)), errOut)
	}
}

// dns_queries counts the retries and the wildcard probes too, so it is more
// than the names asked.
func TestDNSQueriesAreMoreThanTheNamesAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	_, rep, _ := dnsOut(t, "-l", writeList(t, "www.lab.zz", "refused.lab.zz", "x.wild.lab.zz"), "-r", lab.addr, "-a", "-json")
	if asked := int64(rep.Counts["asked"]); asked != 3 || rep.DNSQueries <= asked {
		t.Errorf("asked %d, dns_queries %d: retries (3 for the refused name) and a wildcard probe come on top", asked, rep.DNSQueries)
	}
}

// With -all, -any or -axfr, -json gives a row to every name a resolver
// answered, including one with no record at all (and one it answered with an
// error); a plain A gives a row only to the name that has an A.
func TestDNSAllAnyAndAXFRGiveARowToEveryAnsweredName(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	addLabNames(t, map[string][]string{"empty.lab.zz.": {}})
	l := writeList(t, "www.lab.zz", "nope.lab.zz", "empty.lab.zz", "servfail.lab.zz")
	for _, flag := range []string{"-all", "-any"} {
		ls, rep, _ := dnsOut(t, "-l", l, "-r", lab.addr, flag, "-json")
		r := dnsRows(t, ls)
		if len(r) != 4 || r["www.lab.zz"] == nil || r["nope.lab.zz"]["status_code"] != "NXDOMAIN" || r["empty.lab.zz"]["status_code"] != "NOERROR" || r["servfail.lab.zz"]["status_code"] != "SERVFAIL" {
			t.Errorf("%s: rows %v", flag, ls)
		}
		if rep.Results != 4 {
			t.Errorf("%s: results %d, counts %v", flag, rep.Results, rep.Counts)
		}
	}
	// A plain A asks the same names and gives a row to the one that has an A only.
	ls, _, _ := dnsOut(t, "-l", l, "-r", lab.addr, "-json")
	if r := dnsRows(t, ls); len(r) != 1 || r["www.lab.zz"] == nil {
		t.Errorf("-a: rows %v", ls)
	}
	ls, _, _ = dnsOut(t, "-d", "nope.lab.zz", "-r", lab.addr, "-axfr", "-allow", "lab.zz", "-allow", "127.0.0.1", "-timeout", "300ms", "-json")
	if r := dnsRows(t, ls); r["nope.lab.zz"] == nil {
		t.Errorf("-axfr: a name that does not exist has no row: %v", ls)
	}
}

// -rtf a with no type flag keeps the names that have only AAAA, TXT, MX or
// SRV, that have no record (NODATA), that do not exist and the CNAME-only
// ones, and leaves out the names with an A; in text a kept name prints the
// records it has, so one with none prints nothing.
func TestDNSResponseTypeFilterKeepsTheFiveKindsAndTextPrintsWhatItHas(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	addLabNames(t, map[string][]string{
		"empty.lab.zz.":  {},
		"mx.lab.zz.":     {"MX 10 mail.lab.zz."},
		"cnonly.lab.zz.": {"CNAME _dmarc.lab.zz."},
	})
	names := []string{"www.lab.zz", "v6.lab.zz", "_dmarc.lab.zz", "mx.lab.zz", "_sip._tcp.lab.zz", "empty.lab.zz", "nope.lab.zz", "cnonly.lab.zz", "api.lab.zz"}
	ls, _, _ := dnsOut(t, "-l", writeList(t, names...), "-r", lab.addr, "-rtf", "a", "-json")
	r := dnsRows(t, ls)
	got := make([]string, 0, len(r))
	for h := range r {
		got = append(got, h)
	}
	sort.Strings(got)
	want := []string{"_dmarc.lab.zz", "_sip._tcp.lab.zz", "cnonly.lab.zz", "empty.lab.zz", "mx.lab.zz", "nope.lab.zz", "v6.lab.zz"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("-rtf a keeps %v, want %v (www and api have an A)", got, want)
	}
	// In text a kept name prints the records of the types asked: none of the kept names has an A.
	l := writeList(t, "v6.lab.zz", "_dmarc.lab.zz", "empty.lab.zz", "nope.lab.zz", "www.lab.zz")
	if text, _, _ := dnsOut(t, "-l", l, "-r", lab.addr, "-rtf", "a", "-resp"); len(text) != 0 {
		t.Errorf("text with no type flag: %q, want nothing: the names kept have no A", text)
	}
	if text, _, _ := dnsOut(t, "-l", l, "-r", lab.addr, "-rtf", "a", "-txt", "-resp"); !reflect.DeepEqual(text, []string{"_dmarc.lab.zz [TXT] [v=DMARC1; p=none]"}) {
		t.Errorf("text with -txt: %q, want the TXT of the one kept name that has one", text)
	}
}

// A name whose CNAME points at what is gone gets its -json row with takeover
// when A is among the types asked (the default, -a, -all), and is not counted
// as not resolving; the check reads the A chain, so with only another type
// asked there is none to read.
func TestDNSDanglingCNAMEGetsItsRowWhenAIsAsked(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	// Whatever the type asked, a resolver answers the owner's CNAME, and the target does not exist.
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if strings.ToLower(r.Question[0].Name) == "dangling.lab.zz." && r.Question[0].Qtype != dns.TypeSOA {
			rr, _ := dns.NewRR("dangling.lab.zz. 60 IN CNAME app.gone-co.com.")
			m.Answer = append(m.Answer, rr)
		}
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	addr := pc.LocalAddr().String()
	for _, tc := range []struct {
		args []string
		row  bool
	}{
		{nil, true}, {[]string{"-a"}, true}, {[]string{"-all"}, true}, {[]string{"-a", "-mx"}, true},
		{[]string{"-mx"}, false}, {[]string{"-txt"}, false}, {[]string{"-cname"}, false}, {[]string{"-aaaa"}, false},
	} {
		ls, rep, _ := dnsOut(t, append([]string{"-d", "dangling.lab.zz", "-r", addr, "-j", "-allow", "lab.zz"}, tc.args...)...)
		row := dnsRows(t, ls)["dangling.lab.zz"]
		if got := row != nil && row["takeover"] != nil; got != tc.row || (tc.row && rep.Counts["did not resolve"] != 0) {
			t.Errorf("%v: row %v, counts %v, want a row with takeover: %v", tc.args, row, rep.Counts, tc.row)
		}
	}
}

// -all asks A, AAAA, CNAME, MX, NS, SOA, TXT, SRV and CAA of a name, no AXFR
// (-axfr asks it), no PTR and no ANY; an address gets PTR only.
func TestDNSAllAsksTheNineTypesOfAName(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startTypeLab(t)
	dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-all", "-no-wildcard", "-silent")
	if got, want := lab.types(), []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT"}; !reflect.DeepEqual(got, want) {
		t.Errorf("-all asked %v, want %v", got, want)
	}
	lab.reset()
	dnsOut(t, "-d", "192.0.2.7", "-r", lab.addr, "-all", "-silent")
	if got := lab.types(); !reflect.DeepEqual(got, []string{"PTR"}) {
		t.Errorf("an address under -all was asked %v, want PTR only", got)
	}
	lab.reset()
	dnsOut(t, "-d", "lab.zz", "-r", lab.addr, "-axfr", "-silent", "-allow", "lab.zz", "-allow", "127.0.0.1", "-timeout", "300ms")
	if got := lab.types(); !contains(got, "AXFR") {
		t.Errorf("-axfr asked %v", got)
	}
}

// A name is asked 3 times by default (dnsx's is 2), a name -w generates twice,
// and -retry N given sets it for every name, the generated ones too.
func TestDNSDefaultAttemptsAreThreeAndTwoForGeneratedNames(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	for _, tc := range []struct {
		name string
		args []string
		want int64
	}{
		{"a name given", []string{"-d", "refused.lab.zz"}, 3},
		{"a name -w generated", []string{"-d", "lab.zz", "-w", "refused"}, 2},
		{"-retry 4, a name given", []string{"-d", "refused.lab.zz", "-retry", "4"}, 4},
		{"-retry 4, a name -w generated", []string{"-d", "lab.zz", "-w", "refused", "-retry", "4"}, 4},
		{"-retry 1, a name -w generated", []string{"-d", "lab.zz", "-w", "refused", "-retry", "1"}, 1},
	} {
		lab.asked.Store(0)
		dnsOut(t, append(tc.args, "-r", lab.addr, "-silent", "-no-wildcard")...)
		if got := lab.asked.Load(); got != tc.want {
			t.Errorf("%s: %d questions, want %d", tc.name, got, tc.want)
		}
	}
}

// -dns-rate holds back the queries of -d with -w: a second's worth go out at
// once and the rest at the rate, so 9 words at 4 a second take over a second,
// and without it they take no time at all.
func TestDNSRatePacesTheQueriesOfWordsToo(t *testing.T) {
	t.Chdir(t.TempDir())
	lab := startLab(t)
	words := wlist(t, "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9")
	start := nowMs()
	dnsOut(t, "-d", "lab.zz", "-w", words, "-r", lab.addr, "-silent", "-no-wildcard", "-t", "9")
	if d := nowMs() - start; d > 600 {
		t.Fatalf("9 queries with no pace took %d ms", d)
	}
	start = nowMs()
	dnsOut(t, "-d", "lab.zz", "-w", words, "-r", lab.addr, "-silent", "-no-wildcard", "-dns-rate", "4", "-t", "9")
	if d := nowMs() - start; d < 1100 {
		t.Errorf("9 queries at -dns-rate 4 took %d ms: 5 of them wait for the rate, 250 ms each", d)
	}
}

// -asn asks Team Cymru's DNS service through the resolvers the run uses: the
// questions arrive at the named resolver.
func TestDNSASNAsksCymruThroughYourResolvers(t *testing.T) {
	t.Chdir(t.TempDir())
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var asked []string
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		mu.Lock()
		asked = append(asked, dns.TypeToString[q.Qtype]+" "+name)
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		var rec string
		switch {
		case name == "www.lab.zz." && q.Qtype == dns.TypeA:
			rec = "A 192.0.2.1"
		case name == "1.2.0.192.origin.asn.cymru.com." && q.Qtype == dns.TypeTXT:
			rec = `TXT "64500 | 192.0.2.0/24 | ZZ | lab | 2026-01-01"`
		case name == "as64500.asn.cymru.com." && q.Qtype == dns.TypeTXT:
			rec = `TXT "64500 | ZZ | lab | 2026-01-01 | AZQ-LAB Lab network, ZZ"`
		}
		if rec == "" {
			m.Rcode = dns.RcodeNameError
		} else if rr, err := dns.NewRR(name + " 60 IN " + rec); err == nil {
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	ls, _, code := dnsOut(t, "-d", "www.lab.zz", "-r", pc.LocalAddr().String(), "-asn", "-json", "-no-wildcard")
	asn, _ := dnsRows(t, ls)["www.lab.zz"]["asn"].(map[string]any)
	if code != exitOK || asn["as-number"] != "AS64500" || asn["as-name"] != "AZQ-LAB Lab network, ZZ" {
		t.Fatalf("exit %d, asn %v", code, asn)
	}
	mu.Lock()
	defer mu.Unlock()
	if !contains(asked, "TXT 1.2.0.192.origin.asn.cymru.com.") || !contains(asked, "TXT as64500.asn.cymru.com.") {
		t.Errorf("the resolver was asked %v", asked)
	}
}
