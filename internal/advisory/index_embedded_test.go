package advisory_test

import (
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/advisory"
)

// The index embedded in the binary is built, dated and holds the records of
// products of each class that the KEV catalogue lists.
func TestEmbeddedIndex(t *testing.T) {
	meta, err := advisory.BuiltinMeta()
	if err != nil {
		t.Fatal(err)
	}
	if meta.Generator != advisory.IndexGenerator || meta.Built < "2026-11-01" || meta.Records < 10000 || len(meta.Sources) != 2 {
		t.Fatalf("meta %+v", meta)
	}
	for _, s := range meta.Sources {
		if s.Date == "" || s.URL == "" || s.N == 0 {
			t.Errorf("source %+v", s)
		}
	}
	if !strings.HasPrefix(meta.Label(), "advisory index "+meta.Built+" (") {
		t.Errorf("label %q", meta.Label())
	}
	ix, err := advisory.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	full := ix.Meta()
	full.Names = nil
	if !reflect.DeepEqual(meta, full) {
		t.Errorf("header read %+v, full read %+v", meta, full)
	}
	for _, p := range []pair{
		{"Apache httpd", "2.4.49", "CVE-2021-41773", "affected"},
		{"Apache httpd", "2.4.51", "CVE-2021-41773", "not affected"},
		{"Apache Tomcat", "9.0.30", "CVE-2020-1938", "affected"},
		{"Apache Tomcat", "9.0.31", "CVE-2020-1938", "not affected"},
		{"MongoDB", "7.0.27", "CVE-2025-14847", "affected"},
		{"ActiveMQ", "5.17.3", "CVE-2023-46604", "affected"},
		{"ActiveMQ", "5.17.6", "CVE-2023-46604", "not affected"},
		{"TeamCity", "2023.11.3", "CVE-2024-27198", "affected"},
		{"Drupal", "7.57", "CVE-2018-7600", "affected"},
		{"Drupal", "7.58", "CVE-2018-7600", "not affected"},
	} {
		leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: p.product, Version: p.version}}, ix)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, l := range leads {
			if l.AdvisoryID == p.id {
				found = true
				if l.Label != p.label {
					t.Errorf("%s %s / %s: %q, want %q", p.product, p.version, p.id, l.Label, p.label)
				}
			}
		}
		if !found {
			t.Errorf("%s %s: the embedded index has no %s", p.product, p.version, p.id)
		}
	}
}

// Products the index names under the names azhaq reports: the service
// names of its port scan and the technologies of its page fingerprints.
func TestEmbeddedIndexKnowsTheNamesAzhaqReports(t *testing.T) {
	ix, err := advisory.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nginx", "Apache httpd", "Apache", "OpenSSH", "MySQL", "PostgreSQL", "Redis", "RabbitMQ", "Jenkins", "WordPress", "Drupal", "Apache Tomcat", "Exim", "ProFTPD", "Elasticsearch", "Grafana"} {
		if len(ix.CPEs(name)) == 0 {
			t.Errorf("the embedded index has no product for the name %q", name)
		}
	}
	// A version of the operating system, a protocol or a connector is not a release of a product.
	for _, name := range []string{"Microsoft IIS httpd", "Apache Tomcat/Coyote JSP engine", "Microsoft HTTPAPI httpd"} {
		if got := ix.CPEs(name); len(got) != 0 {
			t.Errorf("%q maps to %v: its version is not a release of that product", name, got)
		}
	}
}

// Every run's plan reads the header: it must not hold the whole header line
// (most of it the names map) or a records buffer.
func TestBuiltinMetaStaysSmall(t *testing.T) {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	if _, err := advisory.BuiltinMeta(); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&b)
	if got := b.TotalAlloc - a.TotalAlloc; got > 128<<10 {
		t.Errorf("BuiltinMeta allocated %d bytes", got)
	}
}

// In the embedded index a bundled library's records under MySQL (curl,
// XStream, OpenSSL: their CNAs name those, not MySQL) say so and rank after
// every MySQL advisory that applies, though they score 9.8.
func TestEmbeddedIndexRanksBundledLibrariesAfterTheProductsOwn(t *testing.T) {
	ix, err := advisory.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 3306, Proto: "tcp", Product: "MySQL", Version: "8.0.15"}}, ix)
	if err != nil {
		t.Fatal(err)
	}
	g := advisory.Group(leads)[0]
	if g.Component != "" {
		t.Errorf("the top advisory %s names another component: %q", g.AdvisoryID, g.Component)
	}
	seenComponent := false
	for _, r := range g.Advisories {
		if r.Label == advisory.LabelNotAffected {
			break
		}
		if r.Component != "" {
			seenComponent = true
		} else if seenComponent {
			t.Fatalf("%s names the product and comes after one that names another", r.ID)
		}
	}
	for id, want := range map[string]string{"CVE-2019-3822": "curl", "CVE-2021-21344": "xstream", "CVE-2021-3711": "OpenSSL"} {
		found := false
		for _, r := range g.Advisories {
			if r.ID == id {
				found = true
				if r.Component != want || r.Label != advisory.LabelAffected {
					t.Errorf("%s: component %q label %q, want %q and affected", id, r.Component, r.Label, want)
				}
			}
		}
		if !found {
			t.Errorf("%s is not among the advisories", id)
		}
	}
}

// The embedded index carries the attack vector of its records: a Redis flaw
// NVD scores AV:L is conditional on local access, a Tomcat one scored AV:N
// is affected as before.
func TestEmbeddedIndexKeepsAnAttackVector(t *testing.T) {
	ix, err := advisory.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	label := func(product, version, id string) advisory.Lead {
		leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: product, Version: version}}, ix)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range leads {
			if l.AdvisoryID == id {
				return l
			}
		}
		t.Fatalf("%s %s has no %s", product, version, id)
		return advisory.Lead{}
	}
	if l := label("Redis", "7.0.0", "CVE-2025-46818"); l.Label != advisory.LabelConditional || !strings.HasPrefix(l.Precondition, "needs local access") {
		t.Errorf("CVE-2025-46818: %q %q", l.Label, l.Precondition)
	}
	if l := label("Apache Tomcat", "9.0.30", "CVE-2020-1938"); l.Label != advisory.LabelAffected || l.Precondition != "" {
		t.Errorf("CVE-2020-1938: %q %q", l.Label, l.Precondition)
	}
}

// The embedded index carries the preconditions a record states in its own
// text: an Apache record that needs mod_rewrite and a nginx one that needs
// HTTP/2 are conditional, with the words they were read from, and rank after
// the matches with nothing open.
func TestEmbeddedIndexKeepsTheNeedsATextStates(t *testing.T) {
	ix, err := advisory.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		product, version, id, need, quote string
	}{
		{"Apache httpd", "2.4.54", "CVE-2024-38475", "mod_rewrite", "Improper escaping of output in mod_rewrite in Apache HTTP Server"},
		{"Apache httpd", "2.4.54", "CVE-2023-25690", "mod_proxy", "mod_proxy configurations on Apache HTTP Server"},
		{"nginx", "1.11.13", "CVE-2023-44487", "HTTP/2", "The HTTP/2 protocol allows a denial of service"},
	} {
		leads, err := advisory.MatchIndex([]advisory.Service{{Host: "h", Port: 80, Product: c.product, Version: c.version}}, ix)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, l := range leads {
			if l.AdvisoryID != c.id {
				continue
			}
			found = true
			if l.Label != advisory.LabelConditional || !slices.Contains(l.Needs, c.need) || !strings.Contains(l.Precondition, `needs `+c.need+`: "`) || !strings.Contains(l.Precondition, c.quote) {
				t.Errorf("%s %s / %s: %q %v %q", c.product, c.version, c.id, l.Label, l.Needs, l.Precondition)
			}
		}
		if !found {
			t.Errorf("%s %s has no %s", c.product, c.version, c.id)
		}
		// The top of the service's lead is a match with nothing open.
		g := advisory.Group(leads)[0]
		if g.Label != advisory.LabelAffected || g.AdvisoryID == c.id || len(g.Needs) != 0 {
			t.Errorf("%s %s: top %s is %s %v", c.product, c.version, g.AdvisoryID, g.Label, g.Needs)
		}
		sawConditional := false
		for _, r := range g.Advisories {
			if r.Label == advisory.LabelConditional {
				sawConditional = true
			}
			if r.Label == advisory.LabelAffected && sawConditional && r.Component == "" {
				t.Errorf("%s %s: %s (affected) is listed after a conditional match", c.product, c.version, r.ID)
				break
			}
		}
	}
}
