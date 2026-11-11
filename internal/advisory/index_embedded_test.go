package advisory_test

import (
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
