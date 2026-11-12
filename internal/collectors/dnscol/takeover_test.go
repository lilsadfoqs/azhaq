package dnscol

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/dnsr"
	"github.com/lilsadfoqs/azhaq/types"
	"github.com/miekg/dns"
)

// A name whose CNAME chain ends at a name that does not exist: on a
// service anyone may create names on, or under a domain nobody holds, it
// is a takeover candidate; a CNAME to the owner's own name is not.
func TestDanglingCNAME(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	zone := map[string]string{
		"azure.example.org.":  "gone-app.azurewebsites.net.",
		"vendor.example.org.": "cdn.forgotten-vendor-xyz.io.",
		"own.example.org.":    "missing.example.org.",
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if target, ok := zone[q.Name]; ok && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target})
		}
		if q.Qtype == dns.TypeSOA && strings.HasSuffix(q.Name, "azurewebsites.net.") {
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeNameError // every CNAME target, and forgotten-vendor-xyz.io itself, does not exist
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	c := New(dnsr.New(dnsr.Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1}))
	got := map[string]map[string]any{}
	for _, host := range []string{"azure.example.org", "vendor.example.org", "own.example.org"} {
		seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": host}}
		_, err := c.Run(context.Background(), seed, func(o types.Observation) error {
			var p map[string]any
			_ = json.Unmarshal(o.Payload, &p)
			got[host] = p
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if f, _ := got["azure.example.org"]["takeover"].(map[string]any); f["service"] != "Azure" || f["strength"] != "dangling" || f["status"] != "candidate" {
		t.Errorf("azure %v", got["azure.example.org"])
	}
	if f, _ := got["vendor.example.org"]["takeover"].(map[string]any); f["service"] != "domain" || f["strength"] != "strong" || f["status"] != "candidate" {
		t.Errorf("vendor %v", got["vendor.example.org"])
	}
	if got["own.example.org"]["takeover"] != nil || got["own.example.org"]["dangling"] != nil {
		t.Errorf("own name %v", got["own.example.org"])
	}
	// The measured fact stands with the provider's list entry or without: the
	// chain, the code of its end and the resolver that gave it.
	for host, target := range map[string]string{"azure.example.org": "gone-app.azurewebsites.net", "vendor.example.org": "cdn.forgotten-vendor-xyz.io"} {
		d, _ := got[host]["dangling"].(map[string]any)
		if d == nil || d["target"] != target || d["rcode"] != "NXDOMAIN" || d["server"] != pc.LocalAddr().String() {
			t.Errorf("%s dangling %v", host, got[host])
		}
	}
}

// A name that only a wildcard answers, with a CNAME to a name that does not
// exist, is no record of the owner's: no dangling measurement is kept for it.
func TestDanglingNotKeptForAWildcardName(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if strings.HasSuffix(q.Name, ".wild.example.org.") && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "gone.vendor-example.net."})
		}
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	c := New(dnsr.New(dnsr.Options{Resolvers: []string{pc.LocalAddr().String()}, PerSecond: -1}))
	var got map[string]any
	seed := types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": "app.wild.example.org"}}
	if _, err := c.Run(context.Background(), seed, func(o types.Observation) error { return json.Unmarshal(o.Payload, &got) }); err != nil {
		t.Fatal(err)
	}
	if got["wildcard"] != true || got["dangling"] != nil {
		t.Errorf("wildcard name %v", got)
	}
}
