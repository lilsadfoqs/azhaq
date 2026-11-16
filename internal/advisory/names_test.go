package advisory

import (
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

const apacheAdvisories = `[
  {"id":"CVE-TEST-2001","affected":[{"package":{"name":"Apache HTTP Server"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.4.49"}]}]}]}
]`

func TestHeaderProductVersionKeepsTheName(t *testing.T) {
	for in, want := range map[string][2]string{
		"Apache Traffic Server/9.1.0": {"Apache Traffic Server", "9.1.0"},
		"Apache Tomcat/9.0.50":        {"Apache Tomcat", "9.0.50"},
		"Apache/2.4.25 (Debian)":      {"Apache", "2.4.25"},
		"Apache-Coyote/1.1":           {"Apache-Coyote", "1.1"},
		"nginx/1.18.0":                {"nginx", "1.18.0"},
		"":                            {"", ""},
	} {
		if p, v := HeaderProductVersion(in); [2]string{p, v} != want {
			t.Errorf("HeaderProductVersion(%q) = %q, %q; want %q", in, p, v, want)
		}
	}
}

// A version is attached to an advisory only for the product the evidence names
// (#518): a Server header or a stored detection that carries another
// product's version reaches no advisory of the HTTP server.
func TestAdvisoryOnlyForTheProductTheHeaderNames(t *testing.T) {
	advs, err := Load([]byte(apacheAdvisories))
	if err != nil {
		t.Fatal(err)
	}
	leads := func(server string, detected ...map[string]string) int {
		row := map[string]any{"url": "http://h.test:8080/", "ip": "10.0.0.5", "server": server}
		if len(detected) > 0 {
			row["detected"] = detected
		}
		return len(Match(Services([]types.StoredObservation{obsOf("azhaq-http", "http", row)}), advs))
	}
	if n := leads("Apache/2.4.40 (Unix)"); n != 1 {
		t.Errorf("Apache/2.4.40: %d leads, want 1", n)
	}
	for _, server := range []string{"Apache-Coyote/1.1", "ApacheBench/2.3", "Apache Tomcat/9.0.50", "Apache Traffic Server/9.1.0"} {
		if n := leads(server); n != 0 {
			t.Errorf("%q: %d leads of the HTTP server, want 0", server, n)
		}
		// A row stored before templates checked the token: the detection
		// named "Apache" with the version of the other product.
		_, v := HeaderProductVersion(server)
		if n := leads(server, map[string]string{"product": "Apache", "version": v, "template": "apache-detect"}); n != 0 {
			t.Errorf("%q with a stored apache-detect hit: %d leads, want 0", server, n)
		}
	}
	// The version of a detection that is Apache's own still counts.
	if n := leads("Apache/2.4.40", map[string]string{"product": "Apache", "version": "2.4.40", "template": "apache-detect"}); n != 1 {
		t.Errorf("a true Apache detection: %d leads, want 1", n)
	}
}

func TestSameProductWithOrWithoutTheVendor(t *testing.T) {
	for _, c := range []struct {
		pkg, product string
		want         bool
	}{
		{"ActiveMQ", "Apache ActiveMQ", true},
		{"Apache Druid", "Druid", true},
		{"Apache HTTP Server", "Apache", true},
		{"Apache HTTP Server", "Apache ActiveMQ", false},
		{"Apache HTTP Server", "Apache Tomcat", false},
		{"Tomcat", "Apache", false},
	} {
		if got := sameProduct(c.pkg, c.product); got != c.want {
			t.Errorf("sameProduct(%q, %q) = %v", c.pkg, c.product, got)
		}
	}
}
