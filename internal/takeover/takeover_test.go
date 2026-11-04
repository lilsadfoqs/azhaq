package takeover

import (
	"strings"
	"testing"
)

func TestByCNAME(t *testing.T) {
	for _, c := range []struct {
		host                   string
		chain                  []string
		gone, registered, want bool
		service                string
	}{
		{"app.example.com", []string{"example-app.azurewebsites.net"}, true, true, true, "Azure"},
		{"app.example.com", []string{"example-app.azurewebsites.net"}, false, true, false, ""}, // it resolves: someone holds it
		{"old.example.com", []string{"cdn.forgotten-vendor.io"}, true, false, true, "domain"},
		{"old.example.com", []string{"cdn.vendor.io"}, true, true, false, ""},              // the vendor's domain exists: nothing to claim from DNS alone
		{"a.example.com", []string{"b.example.com"}, true, false, false, ""},               // the owner's own name
		{"x.example.com", []string{"x.s3.eu-west-1.amazonaws.com"}, true, true, false, ""}, // S3 says so in its page, not in DNS
	} {
		f, ok := ByCNAME(c.host, c.chain, c.gone, c.registered)
		if ok != c.want || f.Service != c.service {
			t.Errorf("%s → %v: %v %+v", c.host, c.chain, ok, f)
		}
	}
}

func TestByPage(t *testing.T) {
	if f, ok := ByPage([]string{"acme.github.io"}, []byte(`<p>There isn't a GitHub Pages site here.</p>`)); !ok || f.Service != "GitHub Pages" || f.Strength != "strong" {
		t.Errorf("github %+v %v", f, ok)
	}
	if f, ok := ByPage([]string{"files.example.com.s3.amazonaws.com"}, []byte(`<Error><Code>NoSuchBucket</Code></Error>`)); !ok || f.Service != "AWS S3" {
		t.Errorf("s3 %+v %v", f, ok)
	}
	// The words on another service's name prove nothing.
	if _, ok := ByPage([]string{"lb.example.net"}, []byte(`There isn't a GitHub Pages site here.`)); ok {
		t.Error("a page's words on another service")
	}
	if _, ok := ByPage(nil, []byte(`<html>welcome</html>`)); ok {
		t.Error("an ordinary page")
	}
}

func TestDomain(t *testing.T) {
	for host, want := range map[string]string{
		"frontend-app-1.us-west-2.elb.amazonaws.com": "amazonaws.com", // a cloud's shared suffix is no registry
		"cdn.forgotten-vendor.io":                    "forgotten-vendor.io",
		"a.b.example.co.uk":                          "example.co.uk",
		"x.github.io":                                "github.io",
	} {
		if got := Domain(host); got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
}

// A dangling finding says it rests on NXDOMAIN alone, and which list entry
// and date it comes from; every dangling suffix has an entry.
func TestDanglingFindingNamesWhatItRestsOn(t *testing.T) {
	for _, c := range []struct{ target, entry string }{
		{"a.azureedge.net", "Azure CDN"}, {"a.azurewebsites.net", "Azure App Service"},
		{"a.elasticbeanstalk.com", "AWS Elastic Beanstalk"}, {"a.fly.dev", "Fly.io"},
	} {
		f, ok := ByCNAME("x.example.com", []string{c.target}, true, true)
		if !ok || f.Strength != "dangling" {
			t.Fatalf("%s: %+v %v", c.target, f, ok)
		}
		if !strings.Contains(f.List, c.entry) || !strings.Contains(f.List, ListRead) {
			t.Errorf("%s: list %q", c.target, f.List)
		}
		if !strings.Contains(f.Evidence, "Candidate, unverified: NXDOMAIN does not show the name is free") {
			t.Errorf("%s: evidence %q", c.target, f.Evidence)
		}
	}
	for _, s := range services {
		if !s.dangling {
			continue
		}
		for _, suf := range s.suffixes {
			if listEntry[suf] == "" {
				t.Errorf("%s has no list entry", suf)
			}
		}
	}
}

// A finding says what it is: a candidate, unless the service itself answered
// that nothing is there (and the name is known to be on that service).
func TestFindingStatus(t *testing.T) {
	d, _ := ByCNAME("x.example.com", []string{"a.azurewebsites.net"}, true, true)
	if d.Status != Candidate || !strings.HasPrefix(d.Evidence, "observed: CNAME to a.azurewebsites.net; a.azurewebsites.net answered NXDOMAIN; ") ||
		!strings.Contains(d.Evidence, "is on Azure") || !strings.Contains(d.Evidence, "no check with Azure was made") {
		t.Errorf("dangling: %+v", d)
	}
	g, _ := ByCNAME("x.example.com", []string{"cdn.nobody-holds-this.io"}, true, false)
	if g.Status != Candidate || g.Strength != "strong" || !strings.Contains(g.Evidence, "may be free to register; no registry was asked") {
		t.Errorf("domain: %+v", g)
	}
	page := []byte(`<p>There isn't a GitHub Pages site here.</p>`)
	if v, _ := ByPage([]string{"acme.github.io"}, page); v.Status != Verified {
		t.Errorf("the service's own page beside a CNAME to it: %+v", v)
	}
	if p, _ := ByPage(nil, page); p.Status != Candidate || p.Strength != "page" {
		t.Errorf("a page with no CNAME known: %+v", p)
	}
	// A finding stored by an earlier version has no status: it is read as what it was.
	for _, c := range []struct {
		f    Finding
		want string
	}{
		{Finding{Strength: "dangling"}, Candidate}, {Finding{Strength: "page"}, Candidate},
		{Finding{Service: "domain", Strength: "strong"}, Candidate}, {Finding{Service: "GitHub Pages", Strength: "strong"}, Verified},
		{Finding{Strength: "strong", Status: Candidate}, Candidate},
	} {
		if got := c.f.Settled().Status; got != c.want {
			t.Errorf("%+v settles to %q, want %q", c.f, got, c.want)
		}
	}
}
