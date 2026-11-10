package urlcol

import (
	"context"
	"slices"
	"testing"

	"github.com/lilsadfoqs/azhaq/types"
)

func hostSeed(h string) types.Seed {
	return types.Seed{Type: types.TypeHostname, Keys: map[string]string{"fqdn": h}}
}

// A scope that names a host and not its domain asks the archives for the
// host alone and lists its archived URLs; the domain is not asked.
func TestScopeOfOneHostAsksTheArchivesForTheHost(t *testing.T) {
	m := newMirror(t, map[string][]string{"0": {"http://www.example.org/a", "http://www.example.org/b?x=1", "http://example.org/other", "http://api.example.org/x"}})
	var got []string
	c := New(Options{Bases: m.bases(), Client: m.Client(), OnURL: func(u, _ string) { got = append(got, u) },
		Hosts: func(h string) bool { return h == "www.example.org" }})
	c.pauses = nil
	seed := hostSeed("www.example.org")
	if c.Skip(seed) {
		t.Fatal("the host the scope names is skipped")
	}
	if n := len(c.Asks(seed)); n != 5 {
		t.Errorf("%d archives asked about the host, want 5", n)
	}
	if _, err := c.Run(context.Background(), seed, func(types.Observation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/wayback", "/cc/idx", "/arquivo"} {
		if q := m.asked(p); len(q) == 0 || q[0].Get("url") != "www.example.org/*" {
			t.Errorf("%s asked %v, want url=www.example.org/*", p, q)
		}
	}
	if q := m.asked("/urlscan"); len(q) == 0 || q[0].Get("q") != "domain:www.example.org" {
		t.Errorf("urlscan asked %v, want the host", q)
	}
	if len(m.asked("/otx")) == 0 {
		t.Error("otx not asked")
	}
	slices.Sort(got)
	if want := []string{"http://www.example.org/a", "http://www.example.org/b?x=1"}; !slices.Equal(got, want) {
		t.Errorf("URLs %v, want %v: the host's own, not its domain's or its siblings'", got, want)
	}
}

// A hostname the scope does not name alone, with or without a scope, is not
// asked: its domain is, when the scope holds it, and a scope that holds the
// domain is asked for the domain as before.
func TestOtherHostnamesAreNotAsked(t *testing.T) {
	m := newMirror(t, pages)
	for name, o := range map[string]Options{
		"no scope":        {},
		"domain in scope": {Hosts: func(string) bool { return false }},
		"other host":      {Hosts: func(h string) bool { return h == "api.example.org" }},
	} {
		o.Bases, o.Client = m.bases(), m.Client()
		c := New(o)
		c.pauses = nil
		seed := hostSeed("www.example.org")
		if !c.Skip(seed) || len(c.Asks(seed)) != 0 {
			t.Errorf("%s: the host is planned", name)
		}
		if _, err := c.Run(context.Background(), seed, func(types.Observation) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.reqs) != 0 {
		t.Errorf("%d requests for hosts nothing names: %v", len(m.reqs), m.reqs)
	}
	var got []string
	if _, _, _, err := run(t, Options{Bases: m.bases(), Client: m.Client(), OnURL: func(u, _ string) { got = append(got, u) },
		Hosts: func(string) bool { return false }}, context.Background()); err != nil {
		t.Fatal(err)
	}
	if q := m.asked("/wayback"); len(q) == 0 || q[0].Get("url") != "*.example.org/*" {
		t.Errorf("the domain asked %v, want *.example.org/*", q)
	}
	if !slices.Contains(got, "http://api.example.org/otx") {
		t.Errorf("a domain seed lost its subdomains: %v", got)
	}
}
