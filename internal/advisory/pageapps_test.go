package advisory

import (
	"sort"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func appsBy(svcs []Service) map[string]Service {
	m := map[string]Service{}
	for _, s := range svcs {
		m[s.Target()+" "+s.Product] = s
	}
	return m
}

// Two names on one address and port serve different root pages: each name
// gets a service of its own for the application its page names, from the
// page title (the port scan's title rules), a generator meta, X-Powered-By or
// the technologies, with a version only where one was stated and the source
// of the name. Libraries, a CDN, analytics, a plain web server and pages below
// the root are not applications of a name.
func TestPageAppsOneServicePerNameAndProduct(t *testing.T) {
	obs := []types.StoredObservation{
		obsOf("azhaq-http", "http", map[string]any{"url": "http://app.test:8080/", "ip": "10.0.0.5", "title": "Grafana", "server": "nginx/1.18.0"}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://docs.test:8080/", "ip": "10.0.0.5", "title": "Docs", "generator": "WordPress 6.4.2"}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://api.test:8080/", "ip": "10.0.0.5", "headers": map[string]string{"x-powered-by": "Express"}}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://blog.test:8080/", "ip": "10.0.0.5",
			"tech": []string{"Drupal", "jQuery:3.6.0", "Bootstrap:5.0.0", "Google Analytics", "Nginx:1.18.0", "Cloudflare"}}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://app.test:8080/panel", "ip": "10.0.0.5", "title": "Prometheus Time Series"}), // not the root
	}
	got := appsBy(Services(obs))
	for target, want := range map[string]struct{ version, source string }{
		"docs.test:8080 WordPress": {"6.4.2", SourceGenerator},
	} {
		s, ok := got[target]
		if !ok || s.Version != want.version || s.Source != want.source {
			t.Errorf("%s: %+v, want %+v (all %v)", target, s, want, keysOf(got))
		}
	}
	anyVer := appsBy(ServicesAnyVersion(obs))
	for target, source := range map[string]string{
		"app.test:8080 Grafana":    SourceTitle,
		"docs.test:8080 WordPress": SourceGenerator,
		"api.test:8080 Express":    SourcePowered,
		"blog.test:8080 Drupal":    SourceTech,
	} {
		s, ok := anyVer[target]
		if !ok || s.Source != source {
			t.Errorf("%s: %+v (all %v)", target, s, keysOf(anyVer))
		}
	}
	if s := anyVer["app.test:8080 Grafana"]; s.Version != "" || s.Banner != "<title>Grafana</title>" || s.Origin != "http://app.test:8080" {
		t.Errorf("a title is no version: %+v", s)
	}
	// What the page-app reader keeps holds no library, no CDN, no analytics and
	// nothing below the root; a plain web server is kept apart, as Plain.
	for _, a := range pageApps(obs) {
		switch a.Target() + " " + a.Product {
		case "app.test:8080 Grafana", "docs.test:8080 WordPress", "api.test:8080 Express", "blog.test:8080 Drupal":
			if a.Plain {
				t.Errorf("%s is no plain server", a.Product)
			}
		case "app.test:8080 nginx", "blog.test:8080 Nginx":
			if !a.Plain {
				t.Errorf("%s is a plain web server", a.Product)
			}
		default:
			t.Errorf("%s (%s) is no application of the name", a.Target()+" "+a.Product, a.Source)
		}
	}
}

// An application the listener's row already names for the same name is not
// repeated; another name that serves the same product is its own row.
func TestPageAppsNotRepeatedWhereTheListenerNamesIt(t *testing.T) {
	obs := []types.StoredObservation{
		obsOf("azhaq-http", "http", map[string]any{"url": "http://a.test:8080/", "ip": "10.0.0.5", "tech": []string{"WordPress:6.4.2"}, "generator": "WordPress 6.4.2"}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://b.test:8080/", "ip": "10.0.0.5", "generator": "WordPress 6.4.2"}),
	}
	var targets []string
	for _, s := range Services(obs) {
		if ProductKey(s.Product) == "wordpress" {
			targets = append(targets, s.Target())
		}
	}
	sort.Strings(targets)
	if len(targets) != 2 || targets[0] != "a.test:8080" || targets[1] != "b.test:8080" {
		t.Errorf("WordPress services %v, want one for a.test and one for b.test", targets)
	}
}

func keysOf(m map[string]Service) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// A product and version a name's root page states are matched against the
// advisories as a listener's are, and the lead names the name and its port.
func TestPageAppVersionIsMatchedLikeAListeners(t *testing.T) {
	advs, err := Load([]byte(`[{"id":"CVE-TEST-0100","summary":"acme cms issue",
	  "affected":[{"package":{"name":"Acme CMS","ecosystem":"test"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"3.5"}]}]}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	obs := []types.StoredObservation{
		obsOf("azhaq-http", "http", map[string]any{"url": "http://wiki.test:8080/", "ip": "10.0.0.5", "generator": "Acme CMS 3.1"}),
		obsOf("azhaq-http", "http", map[string]any{"url": "http://other.test:8080/", "ip": "10.0.0.5", "title": "Acme CMS"}),
	}
	leads := Match(Services(obs), advs)
	if len(leads) != 1 || leads[0].Host != "wiki.test" || leads[0].Port != 8080 || leads[0].Label != LabelAffected || leads[0].VersionSeen != "3.1" {
		t.Errorf("leads %+v", leads)
	}
}
