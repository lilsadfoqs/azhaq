package build

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lilsadfoqs/azhaq/internal/lazyre"
)

func TestNeedsRegexpsCompile(t *testing.T) {
	if err := lazyre.CompileAll(); err != nil {
		t.Fatal(err)
	}
}

// The preconditions a description states are read with their words: the
// protocol of CVE-2023-44487, the module of CVE-2024-38475, and nothing from
// a description that states none.
func TestNeedsOfSampleDescriptions(t *testing.T) {
	const (
		rapidReset = "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023."
		rewrite    = "Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure. \n\nSubstitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag \"UnsafePrefixStat\" can be used to opt back in once ensuring the substitution is appropriately constrained."
		plain      = "Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the request body, exposing the server to HTTP Request Smuggling"
	)
	type want struct{ name, quote string }
	for name, c := range map[string]struct {
		desc, vendor, product string
		want                  []want
	}{
		"a protocol":           {rapidReset, "nginx", "nginx", []want{{"HTTP/2", rapidReset}}},
		"a module":             {rewrite, "apache", "http_server", []want{{"mod_rewrite", "Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows"}}},
		"no condition":         {plain, "apache", "http_server", nil},
		"empty":                {"", "apache", "http_server", nil},
		"configured to":        {"Log4j 1.x is affected when specifically configured to use JMSSink, which is not the default.", "apache", "log4j", []want{{"a configuration", "when specifically configured to use JMSSink"}}},
		"is enabled":           {"Struts 2.3 allows remote attackers to execute code when Dynamic Method Invocation is enabled, via a crafted prefix.", "apache", "struts", []want{{"a feature enabled", "when Dynamic Method Invocation is enabled"}}},
		"a plugin":             {"The vulnerability can only be exploited if the Marketplace plugin is installed and activated.", "acme", "widget", []want{{"a plugin enabled", "if the Marketplace plugin is installed"}}},
		"a non-default":        {"The fix was incomplete in certain non-default configurations of Log4j.", "apache", "log4j", []want{{"a non-default setting", "non-default configurations"}}},
		"a module's own name":  {"The mod_security module allows bypass of rules.", "acme", "mod_security", nil},
		"a vector, not a need": {"GNU Bash processes strings in environment variables, with vectors in the mod_cgi module in Apache.", "gnu", "bash", nil},
		"the fix names it":     {"Users are recommended to upgrade; as a workaround disable mod_proxy.", "apache", "http_server", nil},
		"no protocol alone":    {"For HTTP/1, HTTP/2 and HTTP/3 requests there is no strict host check.", "eclipse", "jetty", nil},
		"on by default":        {"In Apache Tomcat 9.0.0.M1 to 9.0.0.30, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses.", "apache", "tomcat", nil},
		"not enabled":          {"It is used if the native extensions are not enabled.", "adminer", "adminer", nil},
		"no non-default":       {"No non-default configuration is required to reach it.", "apache", "airflow", nil},
	} {
		got := needsOf(c.desc, c.vendor, c.product)
		if len(got) != len(c.want) {
			t.Errorf("%s: %+v, want %d need(s)", name, got, len(c.want))
			continue
		}
		for i, w := range c.want {
			if got[i].Name != w.name || !strings.Contains(got[i].Quote, w.quote) || len(got[i].Quote) > quoteSize+8 {
				t.Errorf("%s: need %+v, want %q quoting %q", name, got[i], w.name, w.quote)
			}
		}
	}
}

// A long sentence is quoted around the words that state the need, with a
// mark where it was cut.
func TestNeedsQuoteCutsALongSentence(t *testing.T) {
	long := strings.Repeat("The parser reads the header and then the body of every request. ", 1)
	long += "A flaw in the second stage, in the HTTP/2 framing code, lets a peer " + strings.Repeat("send frames out of order and exhaust memory ", 12) + "until the process stops."
	got := needsOf(long, "acme", "widget")
	if len(got) != 1 || got[0].Name != "HTTP/2" {
		t.Fatalf("needs %+v", got)
	}
	q := got[0].Quote
	if !strings.Contains(q, "HTTP/2") || !strings.HasSuffix(q, "…") || len(q) > quoteSize+8 {
		t.Errorf("quote %q", q)
	}
}

// The builder reads the English description of each record, keeps its needs
// on the index entry and counts them in the report; a record that states
// none keeps none. A module that is the product itself is no need.
func TestBuildKeepsTheNeedsADescriptionStates(t *testing.T) {
	rec := func(id, desc, cpe string) string {
		d, _ := json.Marshal(desc)
		return `{"cve":{"id":"` + id + `","vulnStatus":"Analyzed","descriptions":[{"lang":"es","value":"Texto"},{"lang":"en","value":` + string(d) + `}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:` + cpe + `:*:*:*:*:*:*:*:*","versionEndExcluding":"2.4.60"}]}]}]}}`
	}
	res, err := withFeed(t, strings.Join([]string{
		rec("CVE-2023-44487", "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.", "apache:http_server"),
		rec("CVE-2024-38475", "Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations.", "apache:http_server"),
		rec("CVE-2022-0001", "Apache HTTP Server fails to close the inbound connection when errors are encountered.", "apache:http_server"),
	}, ","))
	if err != nil {
		t.Fatal(err)
	}
	p := product(res, "apache:http_server")
	for id, want := range map[string]string{"CVE-2023-44487": "HTTP/2", "CVE-2024-38475": "mod_rewrite", "CVE-2022-0001": ""} {
		v, ok := vuln(p, id)
		switch {
		case !ok:
			t.Errorf("%s is not indexed", id)
		case want == "" && len(v.Needs) != 0:
			t.Errorf("%s: needs %+v, want none", id, v.Needs)
		case want != "" && (len(v.Needs) != 1 || v.Needs[0].Name != want || v.Needs[0].Quote == ""):
			t.Errorf("%s: needs %+v, want %s", id, v.Needs, want)
		}
	}
	if r := res.Report; r.NeedRecords != 2 || r.Needs["HTTP/2"] != 1 || r.Needs["module"] != 1 {
		t.Errorf("report: %d records, %v", r.NeedRecords, r.Needs)
	}
}
