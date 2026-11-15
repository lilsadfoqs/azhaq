package detect

import "testing"

func TestProduct(t *testing.T) {
	for in, want := range map[string]string{
		"Grafana Login Panel - Detect":          "Grafana",
		"Apache Solr Admin Panel - Detect":      "Apache Solr Admin",
		"Nginx version detect":                  "Nginx",
		"Wordpress Plugin Detection":            "Wordpress Plugin",
		"Jenkins Dashboard":                     "Jenkins",
		"FingerprintHub Technology Fingerprint": "FingerprintHub Technology",
		"Exposed Kibana Dashboard Panel":        "Kibana",
		"Detect Springboot Actuators":           "Springboot Actuators",
		"Foo-Detect":                            "Foo",
		"Zabbix Login Page Detection":           "Zabbix",
		"Panel":                                 "Panel",
		"Detect":                                "Detect",
		"Pageant":                               "Pageant",
		"Subversion":                            "Subversion",
		"Cisco Web Interface - Login - Detect":  "Cisco Web Interface",
		"  Spaces Panel  ":                      "Spaces",
	} {
		if got := Product(in); got != want {
			t.Errorf("Product(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanise(t *testing.T) {
	for in, want := range map[string]string{
		"atlassian-jira":  "atlassian jira",
		"contact_form_7":  "contact form 7",
		"  -weird_name- ": "weird name",
		"plain":           "plain",
	} {
		if got := Humanise(in); got != want {
			t.Errorf("Humanise(%q) = %q, want %q", in, got, want)
		}
	}
}
