package advisory

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func obsOf(collector, kind string, payload any) types.StoredObservation {
	raw, _ := json.Marshal(payload)
	return types.StoredObservation{Observation: types.Observation{Collector: collector, Kind: kind, Payload: raw}}
}

const jettyAdvisories = `[
  {"id":"CVE-TEST-1001","affected":[{"package":{"name":"Jetty"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"9.0.0"},{"fixed":"9.4.53"}]}]}]},
  {"id":"CVE-TEST-1002","affected":[{"package":{"name":"Jetty"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"9.0.0"},{"fixed":"9.4.40"}]}]}]}
]`

// The Server header and a page technology of one listener are one service
// with the most specific version, and the name, the address and the port
// scan's own row are one listener.
func TestServicesAreOneForAListenerAndProduct(t *testing.T) {
	obs := []types.StoredObservation{
		obsOf("azhaq-http", "http", map[string]any{"url": "http://app.test:8080/", "ip": "10.0.0.5",
			"server": "Jetty/9.4.z-SNAPSHOT", "tech": []string{"Jetty:9.4"}}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://10.0.0.5:8080/", "ip": "10.0.0.5", "server": "Jetty/9.4.z-SNAPSHOT"}),
		obsOf("azhaq-ports", "ports", map[string]any{"host": "10.0.0.5", "ip": "10.0.0.5",
			"services": []map[string]any{{"port": 8080, "service": "http", "product": "Jetty", "version": "9.4"}}}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://other.test:8080/", "server": "Jetty/9.4"}), // an address we do not know
	}
	got := Services(obs)
	if len(got) != 2 {
		t.Fatalf("%d services, want 2 (one listener, and one with no known address): %+v", len(got), got)
	}
	s := got[0]
	if s.Host != "app.test" || s.Version != "9.4.z-SNAPSHOT" || s.Target() != "app.test:8080" || s.Address() != "10.0.0.5" {
		t.Errorf("service %+v, want app.test:8080 at 10.0.0.5 with the most specific version", s)
	}
	if !slices.Equal(s.Names, []string{"10.0.0.5", "app.test"}) {
		t.Errorf("names %v, want both host strings", s.Names)
	}
	if got[1].Host != "other.test" {
		t.Errorf("second service %+v", got[1])
	}
}

// A name that the DNS answer gives one address is the listener of that address.
func TestServicesJoinANameToItsDNSAnswer(t *testing.T) {
	obs := []types.StoredObservation{
		obsOf("azhaq-dns", "dns", map[string]any{"fqdn": "a.test", "ips": []string{"10.0.0.9"}}),
		obsOf("azhaq-dns", "dns", map[string]any{"fqdn": "two.test", "ips": []string{"10.0.0.9", "10.0.0.10"}}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://a.test/", "server": "nginx/1.18.0"}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://10.0.0.9/", "server": "nginx/1.18.0"}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://two.test/", "server": "nginx/1.18.0"}),
	}
	got := Services(obs)
	if len(got) != 2 || got[0].Host != "a.test" || len(got[0].Names) != 2 || got[1].Host != "two.test" {
		t.Fatalf("services %+v, want a.test with 10.0.0.9, and two.test (two addresses) apart", got)
	}
}

// A version that cannot be ordered against a range is conditional and says
// why, never not affected.
func TestAVersionThatCannotBeOrderedIsConditional(t *testing.T) {
	advs, err := Load([]byte(jettyAdvisories))
	if err != nil {
		t.Fatal(err)
	}
	svc := Service{Host: "h", Port: 80, Product: "Jetty", Version: "9.4.z-SNAPSHOT"}
	leads := Match([]Service{svc}, advs)
	if len(leads) != 2 {
		t.Fatalf("%d leads", len(leads))
	}
	for _, l := range leads {
		if l.Label != LabelConditional || !strings.Contains(l.Precondition, "could not be compared") {
			t.Errorf("%s is %q (%q), want conditional with the reason", l.AdvisoryID, l.Label, l.Precondition)
		}
	}
	// A version that can be ordered keeps its exact label.
	if l := Match([]Service{{Host: "h", Port: 80, Product: "Jetty", Version: "9.4.54"}}, advs); l[0].Label != LabelNotAffected {
		t.Errorf("9.4.54 is %q", l[0].Label)
	}
	for _, v := range []string{"9.4.z-SNAPSHOT", "1.2.x", "2.4.a"} {
		if _, ok := Compare(v, "9.4.53"); ok {
			t.Errorf("Compare(%q) made a guess", v)
		}
	}
	for _, v := range []string{"9.4.0-SNAPSHOT", "1.0.beta", "2.0.0.RC1", "3.2.1.RELEASE", "9.6p1"} {
		if _, ok := Compare(v, "9.4.53"); !ok {
			t.Errorf("Compare(%q) refused a version it orders", v)
		}
	}
}

func leadOf(id, label, host, addr string, port int, product string) Lead {
	return Lead{AdvisoryID: id, Label: label, Target: fmt.Sprintf("%s:%d", host, port), Host: host, Address: addr, Port: port,
		Product: product, VersionSeen: "1.0"}
}

// A name and its address are one lead, which lists the names; the same
// advisory id twice in it counts once, as its strongest label.
func TestGroupMakesOneLeadOfAListenerAndProduct(t *testing.T) {
	a := leadOf("CVE-1", LabelAffected, "app.test", "10.0.0.5", 80, "nginx")
	a.Names = []string{"10.0.0.5", "app.test"}
	b := leadOf("CVE-2", LabelAffected, "10.0.0.5", "10.0.0.5", 80, "nginx")
	b.Names = a.Names
	dup := leadOf("CVE-1", LabelConditional, "app.test", "10.0.0.5", 80, "nginx")
	dup.Names = a.Names
	got := Group([]Lead{dup, a, b})
	if len(got) != 1 {
		t.Fatalf("%d leads, want 1", len(got))
	}
	g := got[0]
	if len(g.Advisories) != 2 || g.Counts[LabelAffected] != 2 || g.Counts[LabelConditional] != 0 {
		t.Errorf("advisories %+v counts %v, want CVE-1 once as affected and CVE-2", g.Advisories, g.Counts)
	}
	if line := g.Line(); !strings.Contains(line, "on app.test:80 (also 10.0.0.5): 2 affected") {
		t.Errorf("line %q does not name the other host strings", line)
	}
}

// An advisory that two products of a listener match is one distinct advisory.
func TestDistinctCountsAnAdvisoryOnceOnAListener(t *testing.T) {
	leads := Group([]Lead{
		leadOf("CVE-1", LabelAffected, "h", "10.0.0.5", 80, "nginx"),
		leadOf("CVE-2", LabelConditional, "h", "10.0.0.5", 80, "nginx"),
		leadOf("CVE-1", LabelConditional, "h", "10.0.0.5", 80, "Jetty"),
		leadOf("CVE-1", LabelAffected, "h", "10.0.0.5", 81, "Jetty"),
	})
	if len(leads) != 3 {
		t.Fatalf("%d leads, want 3 (two products on :80, one on :81)", len(leads))
	}
	d := Distinct(leads)
	if d.Advisories != 3 || d.ByLabel[LabelAffected] != 2 || d.ByLabel[LabelConditional] != 1 {
		t.Errorf("distinct %+v, want CVE-1 and CVE-2 on :80 and CVE-1 on :81, CVE-1 :80 as affected", d)
	}
}

// A lead whose matches were not read says so in its one line.
func TestRangeOnlyLeadSaysNothingWasChecked(t *testing.T) {
	ls := []Lead{leadOf("CVE-1", LabelAffected, "h", "", 80, "nginx"), leadOf("CVE-2", LabelAffected, "h", "", 80, "nginx")}
	g := Group(ls)[0]
	if line := g.Line(); !strings.Contains(line, "2 affected") || !strings.Contains(line, "; range match only, no precondition checked") {
		t.Errorf("line %q", line)
	}
	g.Confidence = Observed
	if line := g.Line(); strings.Contains(line, "range match only") {
		t.Errorf("a confirmed lead says range only: %q", line)
	}
}

// Two versions of one product on a listener that do not refine each other
// are both said on the lead; a refinement ("9.4" of "9.4.z-SNAPSHOT") is not.
func TestServicesSayAVersionTheyDidNotPick(t *testing.T) {
	obs := []types.StoredObservation{
		obsOf("azhaq-http", "http", map[string]any{"url": "http://app.test/", "server": "Apache/2.4.49", "tech": []string{"Apache:2.4.52", "Apache:2.4"}}),
	}
	got := Services(obs)
	if len(got) != 1 || got[0].Version != "2.4.49" || !slices.Equal(got[0].AlsoSeen, []string{"2.4.52"}) {
		t.Fatalf("services %+v, want 2.4.49 also seen as 2.4.52 only", got)
	}
	l := leadOf("CVE-1", LabelAffected, "app.test", "", 80, "Apache")
	l.AlsoSeen = got[0].AlsoSeen
	if line := Group([]Lead{l})[0].Line(); !strings.Contains(line, "; also seen as 2.4.52") {
		t.Errorf("line %q", line)
	}
}
