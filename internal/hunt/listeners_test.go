package hunt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/engine"
	"github.com/lilsadfoqs/azhaq/internal/proof"
)

func listener(kind, host string, port int, product, version, advisory, label string) Listener {
	return Listener{Ident: Ident{Kind: kind, Host: host, Port: port, Product: product, Version: version, AdvisoryID: advisory, Label: label, Severity: "info", Evidence: "e"}}
}

// A proved finding comes first, then an identification with a version (a read's label
// before a range match), then a product with no version, then every lead.
func TestListenersRankByTierBesideRoutes(t *testing.T) {
	const o = "http://t.test"
	rows := []engine.MapEntry{urlRow(o+"/admin/login", "page", "visited", 200, nil)}
	got := Build(Input{DB: "w.db", Rows: rows, Now: now, Since: 7 * 24 * 3600e9, Listeners: []Listener{
		listener("identification", "10.0.0.5", 80, "Express", "", "", "version-only"),
		listener("identification", "10.0.0.5", 8161, "ActiveMQ", "5.15.0", "CVE-1", "version-only"),
		listener("finding", "10.0.0.5", 6379, "Redis", "", "", "proved"),
		listener("identification", "10.0.0.5", 21, "ProFTPD", "1.3.5", "CVE-2", "proved"),
		listener("identification", "10.0.0.5", 22, "OpenSSH", "9.6", "", "version-only"),
	}})
	var keys []string
	for _, r := range got {
		keys = append(keys, r.Key)
	}
	want := []string{"10.0.0.5:6379", "10.0.0.5:21", "10.0.0.5:8161", "10.0.0.5:22", "10.0.0.5:80", o + "/admin/login"}
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Fatalf("order %v, want %v", keys, want)
	}
	if got[0].Tier != "finding" || got[1].Tier != "identification" || got[4].Tier != "identification" || got[5].Tier != "lead" {
		t.Errorf("tiers %v %v %v %v", got[0].Tier, got[1].Tier, got[4].Tier, got[5].Tier)
	}
	if r := got[4]; r.Reasons[0].Detail != "Express (no version seen)" {
		t.Errorf("no-version row says %q", r.Reasons[0].Detail)
	}
	raw, _ := json.Marshal(got[2])
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "identification" || m["host"] != "10.0.0.5" || m["port"] != float64(8161) || m["product"] != "ActiveMQ" || m["version"] != "5.15.0" ||
		m["advisory_id"] != "CVE-1" || m["label"] != "version-only" || m["tier"] != "identification" {
		t.Errorf("JSON row %v", m)
	}
}

func TestListenerNextIsTheReproduceCommand(t *testing.T) {
	l := listener("identification", "10.0.0.5", 80, "nginx", "1.18.0", "CVE-3", "version-only")
	l.Proof = &proof.Proof{Excerpt: "Server: nginx/1.18.0", Reproduce: "curl -sS -i http://10.0.0.5/"}
	r := Build(Input{DB: "w.db", Now: now, Listeners: []Listener{l}})
	if len(r) != 1 || r[0].Next != "curl -sS -i http://10.0.0.5/" || r[0].Proof == nil {
		t.Fatalf("%+v", r)
	}
}

// A version a service stated inside an advisory's range ranks below a read that
// proved something and above a range match nothing read: version-read sits
// between proved and version-only.
func TestListenersRankAVersionReadBetweenProvedAndVersionOnly(t *testing.T) {
	got := Build(Input{DB: "w.db", Now: now, Listeners: []Listener{
		listener("identification", "10.0.0.5", 80, "nginx", "1.18.0", "CVE-1", "version-only"),
		listener("identification", "10.0.0.5", 81, "nginx", "1.18.0", "CVE-1", "version-read"),
		listener("identification", "10.0.0.5", 82, "nginx", "1.18.0", "CVE-1", "proved"),
		listener("identification", "10.0.0.5", 83, "nginx", "1.18.0", "CVE-1", "conditional"),
	}})
	var keys []string
	for _, r := range got {
		keys = append(keys, r.Key)
	}
	if want := "10.0.0.5:82 10.0.0.5:81 10.0.0.5:80 10.0.0.5:83"; strings.Join(keys, " ") != want {
		t.Errorf("order %v, want %s", keys, want)
	}
}
